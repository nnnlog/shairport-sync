/*
 * The AirPlay 2 low-latency audio stream. This file is part of Shairport Sync.
 * Copyright (c) 2026 the Shairport Sync contributors
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include "ap2_apat.h"
#include "ap2_apat_codec.h"
#include "common.h"
#include "player.h"
#include "rtp.h"
#include "utilities/network_utilities.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libavcodec/avcodec.h>
#include <poll.h>
#include <pthread.h>
#include <sodium.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

// Two threads, as in Apple's receiver, whose network side and renderer are apart:
// - the network thread receives the datagrams, keeps the feedback records and sends the feedback.
//   It never calls into the player. The player can hold its buffer lock for hundreds of
//   milliseconds (it primes the audio backend under it, and a backend may open its output then);
//   a receiver that stops reading meanwhile reports late arrival times and no feedback, so the
//   sender retransmits what it sent in that time and takes the delay for network latency, which
//   it then keeps as the starting latency of the receiver's next sessions (Apple's
//   APSAdaptiveLatencyManager and its cache).
// - the feed thread follows the play state and gives the frames to the player, in order.
// They share the reorder buffer, under a lock that is held for short copies only, never during a
// call into the player. Neither relies on pthread_cancel: each waits in poll() on a pipe that
// ap2_apat_stop() writes to (the feed thread also on one the network thread writes to when it
// holds a new frame), and the socket is non-blocking.

#define MAX_DATAGRAM_LENGTH 4096
#define MAX_UNIT_LENGTH 4096    // a whole unit, reassembled from fragments if need be
#define RECORD_SLOTS 1024       // feedback records, by sequence number
#define CCFB_DELAY_NS 100000000 // Apple's receiver: feedback within 100 ms of the first new packet
#define NETWORK_WAIT_MS 100     // the longest the network thread waits without a datagram
#define CONTROL_INTERVAL_MS 20  // how often the feed thread looks at the play state
#define STATISTICS_INTERVAL_NS 10000000000LL
// A missing frame is given up on this long before the player needs it, i.e. before its play time
// less the backend buffer: time to decode the next one.
#define RELEASE_MARGIN_NS 5000000
// What the output path adds to the backend buffer between a frame's arrival and its sound: the
// output device's own latency (about 5 ms for a Pixel's low-latency AAudio stream), user space
// (Apple's receiver allows 4 ms) and decoding. See arrivalToRenderLatencyMs in ap2_apat_setup().
#define ARRIVAL_TO_RENDER_ALLOWANCE_S 0.010

typedef struct {
  uint16_t sequence_number;
  uint8_t used;
  uint8_t has_arrival_time; // a first arrival, not a copy from redundancy or a retransmission
  uint64_t arrival_time;
} record_t;

struct ap2_apat_session {
  rtsp_conn_info *conn;
  uint8_t out_key[APAT_KEY_LENGTH]; // the APAT connection's keys
  uint8_t in_key[APAT_KEY_LENGTH];
  ssrc_t ssrc;           // the stream's encoding, from its SETUP
  uint32_t frame_length; // frames per packet
  int udp_socket;
  uint16_t udp_port;
  int stop_pipe[2]; // ap2_apat_stop() writes to it, once
  int feed_pipe[2]; // non-blocking: the network thread wakes the feed thread with it
  int locks_initialised;
  pthread_t network_thread, feed_thread;
  int network_thread_started, feed_thread_started;
  int stopping; // set atomically by ap2_apat_stop()

  // shared by the two threads, under reorder_lock
  pthread_mutex_t reorder_lock;
  int playing; // the feed thread's play state; written under the lock, read atomically elsewhere
  apat_reorder_t reorder;
  int sequence_restarted; // the reorder buffer started a new run: its first frame starts a sequence
  // how the stream started: when its first audio packet came, and how many came before it played
  uint64_t first_unit_time;
  int ever_played;
  uint64_t units_before_play;

  // the network thread's own
  int have_peer;
  struct sockaddr_storage peer; // the sender, from its first authentic packet
  socklen_t peer_length;
  uint32_t media_ssrc; // the high half of the sender's SSRC
  // feedback (RFC 8888), as Apple's receiver gives it: a record is kept for every packet received
  // until the sender's send window (in its RTCP XR) has moved past it, and all of them are
  // reported each time
  record_t records[RECORD_SLOTS];
  int have_records;
  uint16_t lowest_record, highest_record;
  int have_window;
  uint16_t window_begin;
  uint64_t first_unreported_arrival; // 0 if every packet has been reported
  int feedback_due;                  // after an XR
  uint64_t ccfb_index;
  // a packet in fragments, being put together
  int assembling;
  uint16_t fragment_next_sequence_number;
  uint32_t fragment_timestamp;
  size_t fragment_length;
  uint8_t fragment[MAX_UNIT_LENGTH];
  uint8_t prefix[APAT_PREFIX_LENGTH]; // of the last whole unit: for the redundant units after it
  uint8_t plaintext[MAX_DATAGRAM_LENGTH]; // the datagram being taken; its units point into it
  uint64_t statistics_time;

  // the feed thread's own
  uint32_t expected_timestamp;
  uint16_t player_sequence_number;
  uint64_t frames_in_sequence;
  uint8_t access_unit[APAT_MAX_ACCESS_UNIT_LENGTH + AV_INPUT_BUFFER_PADDING_SIZE];
  int first_frame_reported;

  // statistics, under statistics_lock
  pthread_mutex_t statistics_lock;
  uint64_t packets, retransmissions, sender_reports, authentication_failures, malformed_packets;
  uint64_t frames_put, frames_recovered, frames_lost, ccfb_sent;
  int64_t lead_min, lead_max, lead_total;
  uint64_t lead_count;
};

// The audio backend is told when a low-latency stream plays; only the session that turned it on
// turns it off.
static pthread_mutex_t low_latency_output_lock = PTHREAD_MUTEX_INITIALIZER;
static rtsp_conn_info *low_latency_output_owner = NULL;

static void set_low_latency_output(rtsp_conn_info *conn, int on) {
  pthread_mutex_lock(&low_latency_output_lock);
  if (on != 0) {
    low_latency_output_owner = conn;
    config.low_latency_output_active = 1;
  } else if (low_latency_output_owner == conn) {
    low_latency_output_owner = NULL;
    config.low_latency_output_active = 0;
  }
  pthread_mutex_unlock(&low_latency_output_lock);
}

// News about the stream: shown with the statistics when they are on, otherwise at debug `level`.
static void note(int level, const char *format, ...) __attribute__((format(printf, 2, 3)));
static void note(int level, const char *format, ...) {
  char message[1024];
  va_list arguments;
  va_start(arguments, format);
  vsnprintf(message, sizeof(message), format, arguments);
  va_end(arguments);
  if (config.statistics_requested)
    inform("%s", message);
  else
    debug(level, "%s", message);
}

static const char *clock_status_name(int status) {
  switch (status) {
  case clock_ok:
    return "ok";
  case clock_no_anchor_info:
    return "no anchor";
  case clock_service_unavailable:
    return "no NQPTP";
  case clock_access_error:
    return "NQPTP access error";
  case clock_data_unavailable:
    return "no NQPTP data";
  case clock_no_master:
    return "no master clock";
  case clock_version_mismatch:
    return "NQPTP version mismatch";
  case clock_not_synchronised:
    return "not synchronised";
  case clock_not_valid:
    return "master clock too new";
  case clock_not_ready:
    return "not ready";
  default:
    return "unknown";
  }
}

// Thread priority

void ap2_apat_audio_thread_priority(int nice_value) {
#ifdef __linux__
  // on Linux a nice value belongs to a thread, and PRIO_PROCESS with 0 means the calling thread
  if (setpriority(PRIO_PROCESS, 0, nice_value) != 0)
    debug(2, "Low-latency stream: this thread's nice value can't be set to %d: %s.", nice_value,
          strerror(errno));
#else
  (void)nice_value; // elsewhere it would be the whole process's
#endif
}

// Statistics

static void count(struct ap2_apat_session *s, uint64_t *counter) {
  pthread_mutex_lock(&s->statistics_lock);
  (*counter)++;
  pthread_mutex_unlock(&s->statistics_lock);
}

static void report_statistics(struct ap2_apat_session *s, const char *when) {
  pthread_mutex_lock(&s->statistics_lock);
  uint64_t packets = s->packets, retransmissions = s->retransmissions,
           sender_reports = s->sender_reports, authentication_failures = s->authentication_failures,
           malformed_packets = s->malformed_packets, frames_put = s->frames_put,
           frames_recovered = s->frames_recovered, frames_lost = s->frames_lost,
           ccfb_sent = s->ccfb_sent;
  double lead_average = s->lead_count ? (1.0E-6 * s->lead_total) / s->lead_count : 0.0;
  double lead_min = 1.0E-6 * s->lead_min, lead_max = 1.0E-6 * s->lead_max;
  s->lead_count = 0;
  s->lead_total = 0;
  pthread_mutex_unlock(&s->statistics_lock);
  note(2,
       "Connection %d: low-latency stream%s (%s, play %d, clock %s): packets %" PRIu64
       ", retransmitted %" PRIu64 ", sender reports %" PRIu64 ", authentication failures %" PRIu64
       ", malformed %" PRIu64 "; frames played %" PRIu64 ", recovered %" PRIu64 ", lost %" PRIu64
       "; lead min/avg/max %.1f/%.1f/%.1f ms; feedback sent %" PRIu64 ".",
       s->conn->connection_number, when, get_ssrc_name(s->ssrc),
       __atomic_load_n(&s->playing, __ATOMIC_ACQUIRE),
       clock_status_name(get_ptp_anchor_local_time_info(s->conn, NULL, NULL)), packets,
       retransmissions, sender_reports, authentication_failures, malformed_packets, frames_put,
       frames_recovered, frames_lost, lead_min, lead_average, lead_max, ccfb_sent);
}

// Pipes

static void wake(int fd) {
  char c = 0;
  ssize_t written;
  do
    written = write(fd, &c, 1);
  while ((written < 0) && (errno == EINTR));
  // a full pipe (EAGAIN, the feed pipe being non-blocking) wakes its reader all the same
}

static void drain(int fd) {
  char buffer[64];
  while (read(fd, buffer, sizeof(buffer)) > 0)
    ;
}

// Feedback records (the network thread)

static record_t *record_for(struct ap2_apat_session *s, uint16_t sequence_number) {
  record_t *r = &s->records[sequence_number % RECORD_SLOTS];
  return ((r->used != 0) && (r->sequence_number == sequence_number)) ? r : NULL;
}

static void note_arrival(struct ap2_apat_session *s, uint16_t sequence_number, int has_arrival_time,
                         uint64_t now) {
  if ((s->have_window != 0) && ((int16_t)(sequence_number - s->window_begin) < 0))
    return; // before the sender's window: it no longer needs to hear about it
  if (record_for(s, sequence_number) != NULL)
    return; // already received
  record_t *r = &s->records[sequence_number % RECORD_SLOTS];
  r->used = 1;
  r->sequence_number = sequence_number;
  r->has_arrival_time = has_arrival_time;
  r->arrival_time = now;
  if (s->have_records == 0) {
    s->have_records = 1;
    s->lowest_record = s->highest_record = sequence_number;
  } else {
    if ((int16_t)(sequence_number - s->highest_record) > 0)
      s->highest_record = sequence_number;
    if ((int16_t)(sequence_number - s->lowest_record) < 0)
      s->lowest_record = sequence_number;
  }
  if ((uint16_t)(s->highest_record - s->lowest_record) >= RECORD_SLOTS)
    s->lowest_record = s->highest_record - (RECORD_SLOTS - 1);
}

// The sender's RTCP XR gives its send window: records before it are dropped.
static void note_window(struct ap2_apat_session *s, uint16_t begin) {
  s->have_window = 1;
  s->window_begin = begin;
  if ((s->have_records != 0) && ((int16_t)(begin - s->lowest_record) > 0)) {
    if ((int16_t)(begin - s->highest_record) > 0)
      s->have_records = 0;
    else
      s->lowest_record = begin;
  }
}

static void send_feedback(struct ap2_apat_session *s) {
  s->first_unreported_arrival = 0;
  s->feedback_due = 0;
  if ((s->have_peer == 0) || (s->have_records == 0))
    return;
  int count_reported = (uint16_t)(s->highest_record - s->lowest_record) + 1;
  uint16_t begin = s->lowest_record;
  if (count_reported > APAT_CCFB_MAX_REPORTS) {
    begin = s->highest_record - (APAT_CCFB_MAX_REPORTS - 1);
    count_reported = APAT_CCFB_MAX_REPORTS;
  }
  uint16_t metrics[APAT_CCFB_MAX_REPORTS];
  uint64_t now = get_absolute_time_in_ns();
  int i;
  for (i = 0; i < count_reported; i++) {
    const record_t *r = record_for(s, begin + i);
    if (r == NULL)
      metrics[i] = 0; // not received
    else if (r->has_arrival_time)
      metrics[i] = apat_ccfb_metric(now - r->arrival_time);
    else
      metrics[i] = APAT_CCFB_METRIC_NO_ARRIVAL_TIME;
  }
  uint8_t packet[64 + APAT_CCFB_MAX_REPORTS * 2];
  size_t length = apat_build_ccfb(packet, sizeof(packet), s->media_ssrc, begin, metrics,
                                  count_reported, apat_ntp_middle_32(now), s->ccfb_index, s->in_key);
  if (length == 0)
    return;
  if (sendto(s->udp_socket, packet, length, MSG_DONTWAIT, (struct sockaddr *)&s->peer,
             s->peer_length) == (ssize_t)length) {
    s->ccfb_index++;
    count(s, &s->ccfb_sent);
  }
}

// The player (the feed thread)

// When a frame that is still missing must be given up on: its play time, less the backend buffer
// and a margin. Returns -1 if the play time isn't known yet.
static int frame_deadline(struct ap2_apat_session *s, uint32_t timestamp, uint64_t *deadline) {
  uint64_t play_time;
  if (frame_to_local_time(timestamp, &play_time, s->conn) != 0)
    return -1;
  *deadline = play_time - (uint64_t)(backend_buffer_desired_length(s->conn) * 1.0E9) -
              RELEASE_MARGIN_NS;
  return 0;
}

// Give the frame in s->access_unit to the player. Frames come here in order; a missing one is
// passed on as a timestamp gap, which the player fills with silence. `first_unit_time` and
// `units_before_play` describe the start of the stream, for the note on its first frame.
static void put_frame(struct ap2_apat_session *s, uint32_t timestamp, size_t length,
                      int recovered, uint64_t first_unit_time, uint64_t units_before_play) {
  rtsp_conn_info *conn = s->conn;
  int32_t timestamp_gap = 0;
  uint64_t lost = 0;
  if (s->frames_in_sequence != 0) {
    timestamp_gap = (int32_t)(timestamp - s->expected_timestamp);
    if (timestamp_gap > 0)
      lost = timestamp_gap / s->frame_length;
  }
  // the first frame of a sequence is decoded but muted, as with buffered AAC
  int mute = (s->frames_in_sequence == 0);
  memset(s->access_unit + length, 0, AV_INPUT_BUFFER_PADDING_SIZE);
  if (s->first_frame_reported == 0) {
    s->first_frame_reported = 1;
    note(2,
         "Connection %d: low-latency stream: first frame %.1f ms after the first audio packet; "
         "%" PRIu64 " packets came before play began.",
         conn->connection_number,
         first_unit_time ? 1.0E-6 * (get_absolute_time_in_ns() - first_unit_time) : 0.0,
         units_before_play);
  }
  uint32_t frames = player_put_packet(s->ssrc, s->player_sequence_number, timestamp,
                                      s->access_unit, length, mute, timestamp_gap, conn,
                                      s->player_sequence_number);
  note_ptp_rtp_timestamp(conn, timestamp);

  uint64_t play_time;
  int have_lead = (frame_to_local_time(timestamp, &play_time, conn) == 0);
  int64_t lead = have_lead ? (int64_t)(play_time - get_absolute_time_in_ns()) : 0;
  pthread_mutex_lock(&s->statistics_lock);
  s->frames_lost += lost;
  if (recovered != 0)
    s->frames_recovered++;
  s->frames_put++;
  if (have_lead) {
    if ((s->lead_count == 0) || (lead < s->lead_min))
      s->lead_min = lead;
    if ((s->lead_count == 0) || (lead > s->lead_max))
      s->lead_max = lead;
    s->lead_total += lead;
    s->lead_count++;
  }
  pthread_mutex_unlock(&s->statistics_lock);

  s->player_sequence_number++;
  s->expected_timestamp = timestamp + (frames ? frames : s->frame_length);
  s->frames_in_sequence++;
}

// Release the frames that can go to the player now: in order, giving up on a missing frame when
// its time runs out. The reorder lock is held only to look at the buffer and to copy a frame out.
static void release_frames(struct ap2_apat_session *s) {
  while (s->playing != 0) {
    pthread_mutex_lock(&s->reorder_lock);
    int waiting = apat_reorder_waiting(&s->reorder);
    uint32_t next_timestamp = s->reorder.next_timestamp;
    pthread_mutex_unlock(&s->reorder_lock);
    int give_up = 0;
    if (waiting) {
      uint64_t deadline;
      give_up = (frame_deadline(s, next_timestamp, &deadline) != 0) ||
                (get_absolute_time_in_ns() >= deadline);
    }
    pthread_mutex_lock(&s->reorder_lock);
    // (if the missing frame came meanwhile, giving up on it releases it all the same)
    apat_reorder_slot_t *frame = apat_reorder_release(&s->reorder, give_up);
    uint32_t timestamp = 0;
    size_t length = 0;
    int recovered = 0, restarted = 0;
    uint64_t first_unit_time = s->first_unit_time, units_before_play = s->units_before_play;
    if (frame != NULL) {
      timestamp = frame->timestamp;
      length = frame->length;
      recovered = frame->recovered;
      memcpy(s->access_unit, frame->data, length);
      restarted = s->sequence_restarted;
      s->sequence_restarted = 0;
    }
    pthread_mutex_unlock(&s->reorder_lock);
    if (frame == NULL)
      break;
    if (restarted != 0)
      s->frames_in_sequence = 0; // the timestamps jumped: a new sequence
    put_frame(s, timestamp, length, recovered, first_unit_time, units_before_play);
  }
}

static void set_playing(struct ap2_apat_session *s, int playing) {
  pthread_mutex_lock(&s->reorder_lock);
  apat_reorder_reset(&s->reorder, s->frame_length);
  s->sequence_restarted = 0;
  if (playing != 0)
    s->ever_played = 1;
  __atomic_store_n(&s->playing, playing, __ATOMIC_RELEASE);
  pthread_mutex_unlock(&s->reorder_lock);
}

// Follow the play state, which the RTSP requests set: play needs the player thread to have started,
// the sender's rate to be 1 and a valid anchor. A pause or a flush stops the audio at once.
static void follow_play_state(struct ap2_apat_session *s) {
  rtsp_conn_info *conn = s->conn;
  pthread_mutex_lock(&conn->flush_mutex);
  int rate_is_play = conn->ap2_play_enabled;
  int flush = conn->ap2_immediate_flush_requested;
  conn->ap2_immediate_flush_requested = 0; // the low-latency stream flushes at once
  pthread_mutex_unlock(&conn->flush_mutex);
  int player_ready = __atomic_load_n(&conn->player_thread_ready, __ATOMIC_ACQUIRE);
  int playing = (rate_is_play != 0) && (player_ready != 0) && have_ptp_timing_information(conn);
  if ((playing != s->playing) || (flush != 0)) {
    int was_playing = s->playing;
    set_playing(s, 0); // the network thread holds no frames from now on
    if ((was_playing != 0) && (player_ready != 0))
      reset_buffer(conn); // stop what is queued for output; it may wait for the player
    debug(2, "Connection %d: low-latency stream: %s.", conn->connection_number,
          flush ? "flushed" : (playing ? "play" : "pause"));
    s->frames_in_sequence = 0;
    if (playing != 0)
      set_playing(s, 1);
  }
}

// How long the feed thread waits, in ms: until a missing frame's deadline or the next look at the
// play state, whichever is first.
static int feed_wait_time(struct ap2_apat_session *s) {
  int64_t wait = CONTROL_INTERVAL_MS * 1000000LL;
  if (s->playing != 0) {
    pthread_mutex_lock(&s->reorder_lock);
    int waiting = apat_reorder_waiting(&s->reorder);
    uint32_t next_timestamp = s->reorder.next_timestamp;
    pthread_mutex_unlock(&s->reorder_lock);
    uint64_t deadline;
    if (waiting && (frame_deadline(s, next_timestamp, &deadline) == 0)) {
      int64_t until = (int64_t)(deadline - get_absolute_time_in_ns());
      if (until < wait)
        wait = until;
    }
  }
  return (wait <= 0) ? 0 : (int)(wait / 1000000) + 1;
}

static void *feed_thread(void *arg) {
  struct ap2_apat_session *s = (struct ap2_apat_session *)arg;
  ap2_apat_audio_thread_priority(-16);
  struct pollfd fds[2];
  fds[0].fd = s->feed_pipe[0];
  fds[0].events = POLLIN;
  fds[1].fd = s->stop_pipe[0];
  fds[1].events = POLLIN;
  while (__atomic_load_n(&s->stopping, __ATOMIC_ACQUIRE) == 0) {
    fds[0].revents = 0;
    fds[1].revents = 0;
    int ready = poll(fds, 2, feed_wait_time(s));
    if ((ready < 0) && (errno != EINTR)) {
      debug(1, "Connection %d: low-latency stream: poll error %d.", s->conn->connection_number,
            errno);
      break;
    }
    if ((ready > 0) && (fds[1].revents != 0))
      break; // ap2_apat_stop()
    if ((ready > 0) && (fds[0].revents != 0))
      drain(s->feed_pipe[0]);
    follow_play_state(s);
    release_frames(s);
  }
  return NULL;
}

// Datagrams (the network thread)

// A whole unit (one APAP-RTP packet): held for the feed thread, if it is playing.
static void take_whole_unit(struct ap2_apat_session *s, const apat_unit_t *unit, int recovered,
                            uint64_t now) {
  uint64_t time_value;
  uint32_t time_scale;
  apap_body_t body;
  if (apat_unit_body(unit, s->prefix, &time_value, &time_scale, &body) != 0) {
    count(s, &s->malformed_packets);
    return;
  }
  if (body.frame_length == 0)
    return;
  int held = 0;
  pthread_mutex_lock(&s->reorder_lock);
  if (s->first_unit_time == 0)
    s->first_unit_time = now;
  if ((s->playing == 0) && (s->ever_played == 0) && (recovered == 0))
    s->units_before_play++;
  if (s->playing != 0) {
    held = apat_reorder_add(&s->reorder, unit->timestamp, body.frame, body.frame_length, recovered);
    if (held < 0)
      s->sequence_restarted = 1;
  }
  pthread_mutex_unlock(&s->reorder_lock);
  if (held < 0)
    debug(2, "Connection %d: low-latency stream: the timestamps jumped; starting again.",
          s->conn->connection_number);
  if (held != 0)
    wake(s->feed_pipe[1]);
}

static void take_unit(struct ap2_apat_session *s, const apat_unit_t *unit, int retransmission,
                      uint64_t now) {
  int recovered = (unit->redundant != 0) || (retransmission != 0);
  note_arrival(s, unit->sequence_number, recovered == 0, now);
  switch (unit->payload_type) {
  case APAT_PAYLOAD_TYPE_WHOLE:
  case APAT_PAYLOAD_TYPE_REDUNDANT:
    take_whole_unit(s, unit, recovered, now);
    break;
  case APAT_PAYLOAD_TYPE_FIRST_FRAGMENT:
    s->assembling = 0;
    if (unit->length <= sizeof(s->fragment)) {
      memcpy(s->fragment, unit->data, unit->length);
      s->fragment_length = unit->length;
      s->fragment_timestamp = unit->timestamp;
      s->fragment_next_sequence_number = unit->sequence_number + 1;
      s->assembling = 1;
    }
    break;
  case APAT_PAYLOAD_TYPE_MIDDLE_FRAGMENT:
  case APAT_PAYLOAD_TYPE_LAST_FRAGMENT:
    // the fragments of a packet have consecutive sequence numbers and the same timestamp
    if ((s->assembling == 0) || (unit->sequence_number != s->fragment_next_sequence_number) ||
        (unit->timestamp != s->fragment_timestamp) ||
        (s->fragment_length + unit->length > sizeof(s->fragment))) {
      s->assembling = 0;
      break;
    }
    memcpy(s->fragment + s->fragment_length, unit->data, unit->length);
    s->fragment_length += unit->length;
    s->fragment_next_sequence_number++;
    if (unit->payload_type == APAT_PAYLOAD_TYPE_LAST_FRAGMENT) {
      apat_unit_t whole = *unit;
      whole.payload_type = APAT_PAYLOAD_TYPE_WHOLE;
      whole.data = s->fragment;
      whole.length = s->fragment_length;
      s->assembling = 0;
      take_whole_unit(s, &whole, recovered, now);
    }
    break;
  default:
    break;
  }
}

static void take_datagram(struct ap2_apat_session *s, const uint8_t *packet, size_t length,
                          const struct sockaddr_storage *from, socklen_t from_length,
                          uint64_t now) {
  apat_datagram_t datagram;
  int response = apat_open_datagram(packet, length, s->out_key, s->plaintext,
                                    sizeof(s->plaintext), &datagram);
  if (response == -1) {
    count(s, &s->authentication_failures);
    return;
  }
  if (response != 0) {
    count(s, &s->malformed_packets);
    return;
  }
  if (s->have_peer == 0) {
    memcpy(&s->peer, from, from_length);
    s->peer_length = from_length;
    s->have_peer = 1;
  }
  if (s->first_unreported_arrival == 0)
    s->first_unreported_arrival = now;
  if (datagram.kind == apat_datagram_xr) {
    count(s, &s->sender_reports);
    if (datagram.has_window)
      note_window(s, datagram.window_begin);
    s->feedback_due = 1; // Apple's receiver answers an XR at once
    return;
  }
  count(s, &s->packets);
  if (datagram.retransmission)
    count(s, &s->retransmissions);
  s->media_ssrc = datagram.ssrc & 0xFFFF0000;
  int i;
  for (i = 0; i < datagram.unit_count; i++)
    take_unit(s, &datagram.units[i], datagram.retransmission, now);
}

// How long the network thread waits for a datagram, in ms: until the feedback is due, if a packet
// awaits it.
static int network_wait_time(struct ap2_apat_session *s) {
  int64_t wait = NETWORK_WAIT_MS * 1000000LL;
  if (s->first_unreported_arrival != 0) {
    int64_t until =
        (int64_t)(s->first_unreported_arrival + CCFB_DELAY_NS - get_absolute_time_in_ns());
    if (until < wait)
      wait = until;
  }
  return (wait <= 0) ? 0 : (int)(wait / 1000000) + 1;
}

static void *network_thread(void *arg) {
  struct ap2_apat_session *s = (struct ap2_apat_session *)arg;
  ap2_apat_audio_thread_priority(-16);
  uint8_t packet[MAX_DATAGRAM_LENGTH];
  s->statistics_time = get_absolute_time_in_ns();
  struct pollfd fds[2];
  fds[0].fd = s->udp_socket;
  fds[0].events = POLLIN;
  fds[1].fd = s->stop_pipe[0];
  fds[1].events = POLLIN;
  while (__atomic_load_n(&s->stopping, __ATOMIC_ACQUIRE) == 0) {
    fds[0].revents = 0;
    fds[1].revents = 0;
    int ready = poll(fds, 2, network_wait_time(s));
    if ((ready < 0) && (errno != EINTR)) {
      debug(1, "Connection %d: low-latency stream: poll error %d.", s->conn->connection_number,
            errno);
      break;
    }
    if ((ready > 0) && (fds[1].revents != 0))
      break; // ap2_apat_stop()
    while (1) {
      struct sockaddr_storage from;
      socklen_t from_length = sizeof(from);
      ssize_t length = recvfrom(s->udp_socket, packet, sizeof(packet), MSG_DONTWAIT,
                                (struct sockaddr *)&from, &from_length);
      if (length < 0) {
        if ((errno != EAGAIN) && (errno != EWOULDBLOCK) && (errno != EINTR))
          debug(1, "Connection %d: low-latency stream: receive error %d.",
                s->conn->connection_number, errno);
        break;
      }
      take_datagram(s, packet, (size_t)length, &from, from_length, get_absolute_time_in_ns());
    }
    uint64_t now = get_absolute_time_in_ns();
    if ((s->feedback_due != 0) ||
        ((s->first_unreported_arrival != 0) && (now >= s->first_unreported_arrival + CCFB_DELAY_NS)))
      send_feedback(s);
    if (now - s->statistics_time >= STATISTICS_INTERVAL_NS) {
      s->statistics_time = now;
      report_statistics(s, "");
    }
  }
  return NULL;
}

// Setup and teardown

static void free_session(struct ap2_apat_session *s) {
  if (s->udp_socket >= 0)
    safe_socket_close(&s->udp_socket);
  int i;
  for (i = 0; i < 2; i++) {
    if (s->stop_pipe[i] >= 0)
      close(s->stop_pipe[i]);
    if (s->feed_pipe[i] >= 0)
      close(s->feed_pipe[i]);
  }
  if (s->locks_initialised) {
    pthread_mutex_destroy(&s->reorder_lock);
    pthread_mutex_destroy(&s->statistics_lock);
  }
  sodium_memzero(s->out_key, sizeof(s->out_key));
  sodium_memzero(s->in_key, sizeof(s->in_key));
  free(s);
}

static int make_non_blocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  return ((flags == -1) || (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)) ? -1 : 0;
}

int ap2_apat_setup(rtsp_conn_info *conn, plist_t stream, plist_t reply_stream) {
  ap2_apat_stop(conn);

  plist_t connections = plist_dict_get_item(stream, "streamConnections");
  plist_t apat =
      connections ? plist_dict_get_item(connections, "streamConnectionTypeAPAT") : NULL;
  plist_t item = apat ? plist_dict_get_item(apat, "streamConnectionKeyEncryptionSeed") : NULL;
  if (item == NULL) {
    warn("Connection %d: low-latency stream SETUP without an encryption seed.",
         conn->connection_number);
    return -1;
  }
  uint64_t seed = 0;
  plist_get_uint_val(item, &seed); // a negative value is taken as its 64 bits, unsigned
  item = plist_dict_get_item(apat, "streamConnectionKeyTransportProtocol");
  char *transport = NULL;
  if (item != NULL)
    plist_get_string_val(item, &transport);
  int udp = (transport == NULL) || (strcmp(transport, "UDP") == 0);
  if (udp == 0)
    warn("Connection %d: low-latency stream over \"%s\" is not supported.",
         conn->connection_number, transport);
  free(transport);
  if (udp == 0)
    return -1;

  // The encoding: AAC-ELD 48k, the sender's choice when the receiver offers it, or ALAC 44.1k,
  // its fallback otherwise.
  uint64_t audio_format = 0, frames_per_packet = 0;
  item = plist_dict_get_item(stream, "audioFormat");
  if (item != NULL)
    plist_get_uint_val(item, &audio_format);
  item = plist_dict_get_item(stream, "spf");
  if (item != NULL)
    plist_get_uint_val(item, &frames_per_packet);
  ssrc_t ssrc;
  if (audio_format == 0x2000000) {
    ssrc = AAC_ELD_48000_F24_2;
  } else if (audio_format == 0x40000) {
    ssrc = ALAC_44100_S16_2;
  } else {
    warn("Connection %d: low-latency stream with an unsupported format, 0x%" PRIx64 ".",
         conn->connection_number, audio_format);
    return -1;
  }
  if (frames_per_packet == 0)
    frames_per_packet = get_ssrc_block_length(ssrc);
  if ((conn->pair_setup_result == NULL) || (conn->pair_setup_result->shared_secret_len == 0)) {
    warn("Connection %d: low-latency stream SETUP without a pair-setup shared secret.",
         conn->connection_number);
    return -1;
  }

  struct ap2_apat_session *s = calloc(1, sizeof(struct ap2_apat_session));
  if (s == NULL)
    return -1;
  s->conn = conn;
  s->ssrc = ssrc;
  s->frame_length = (uint32_t)frames_per_packet;
  s->udp_socket = -1;
  s->stop_pipe[0] = s->stop_pipe[1] = -1;
  s->feed_pipe[0] = s->feed_pipe[1] = -1;
  apat_derive_keys(conn->pair_setup_result->shared_secret,
                   conn->pair_setup_result->shared_secret_len, seed, s->out_key, s->in_key);
  apat_reorder_reset(&s->reorder, s->frame_length);

  if ((pthread_mutex_init(&s->reorder_lock, NULL) != 0) ||
      (pthread_mutex_init(&s->statistics_lock, NULL) != 0)) {
    // (a failing pthread_mutex_init leaves nothing to destroy)
    free_session(s);
    return -1;
  }
  s->locks_initialised = 1;
  if (pipe(s->stop_pipe) != 0) {
    s->stop_pipe[0] = s->stop_pipe[1] = -1;
    free_session(s);
    return -1;
  }
  if (pipe(s->feed_pipe) != 0) {
    s->feed_pipe[0] = s->feed_pipe[1] = -1;
    free_session(s);
    return -1;
  }
  if ((make_non_blocking(s->feed_pipe[0]) != 0) || (make_non_blocking(s->feed_pipe[1]) != 0)) {
    free_session(s);
    return -1;
  }
  if (bind_socket_and_port(SOCK_DGRAM, conn->connection_ip_family, conn->self_ip_string,
                           conn->self_scope_id, &s->udp_port, &s->udp_socket) != 0) {
    s->udp_socket = -1;
    free_session(s);
    return -1;
  }
  int receive_buffer_size = 1024 * 1024;
  setsockopt(s->udp_socket, SOL_SOCKET, SO_RCVBUF, &receive_buffer_size,
             sizeof(receive_buffer_size));
  if (make_non_blocking(s->udp_socket) != 0) {
    free_session(s);
    return -1;
  }

  // a decoding chain left from an earlier stream is cleared now, while no player runs
  clear_decoding_chain(conn);
  conn->low_latency_stream = 1;
  set_low_latency_output(conn, 1);
  conn->ap2_apat = s;
  if (named_pthread_create_with_priority(&s->network_thread, 2, network_thread, s, "ap2_ll_%d",
                                         conn->connection_number) != 0) {
    ap2_apat_stop(conn);
    return -1;
  }
  s->network_thread_started = 1;
  if (named_pthread_create_with_priority(&s->feed_thread, 2, feed_thread, s, "ap2_llf_%d",
                                         conn->connection_number) != 0) {
    ap2_apat_stop(conn);
    return -1;
  }
  s->feed_thread_started = 1;

  // the reply, as Apple's receivers give it: {streamConnections: {APAT: {port}}}
  plist_t connection = plist_new_dict();
  plist_dict_set_item(connection, "streamConnectionKeyPort", plist_new_uint(s->udp_port));
  plist_t reply_connections = plist_new_dict();
  plist_dict_set_item(reply_connections, "streamConnectionTypeAPAT", connection);
  plist_dict_set_item(reply_stream, "streamConnections", reply_connections);
  // and the time from a frame's arrival to its sound, which the sender adds to the stream's latency
  // ("trailing" latency, with its own and the network's). Apple's receiver gives its output
  // device's latency and IO buffer, plus 4 ms (WifiArrivalToRenderLatencyMs); without it the sender
  // plans no time at all for the backend buffer.
  uint64_t arrival_to_render_ms = (uint64_t)(
      (backend_buffer_desired_length(conn) + ARRIVAL_TO_RENDER_ALLOWANCE_S) * 1000.0 + 0.5);
  plist_dict_set_item(reply_stream, "arrivalToRenderLatencyMs",
                      plist_new_uint(arrival_to_render_ms));

  note(1,
       "Connection %d: low-latency stream set up: %s, %u frames per packet, audio on UDP port %u, "
       "backend buffer %.3f seconds, arrival to render %" PRIu64 " ms.",
       conn->connection_number, get_ssrc_name(ssrc), s->frame_length, s->udp_port,
       backend_buffer_desired_length(conn), arrival_to_render_ms);
  return 0;
}

void ap2_apat_stop(rtsp_conn_info *conn) {
  // nothing here may be left half done by a cancellation
  int old_state;
  pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old_state);
  struct ap2_apat_session *s = conn->ap2_apat;
  if (s != NULL) {
    conn->ap2_apat = NULL;
    __atomic_store_n(&s->stopping, 1, __ATOMIC_RELEASE);
    wake(s->stop_pipe[1]); // both threads see it; nobody reads it
    if (s->network_thread_started)
      pthread_join(s->network_thread, NULL);
    if (s->feed_thread_started)
      pthread_join(s->feed_thread, NULL);
    if (s->network_thread_started)
      report_statistics(s, " stopped");
    conn->low_latency_stream = 0;
    set_low_latency_output(conn, 0);
    free_session(s);
  }
  pthread_setcancelstate(old_state, NULL);
}

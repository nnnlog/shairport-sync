/*
 * Packet formats of AirPlay 2's APAT and APAP audio. This file is part of Shairport Sync.
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

#ifndef _AP2_APAT_CODEC_H
#define _AP2_APAT_CODEC_H

// APAP is the packet format a sender's buffered audio engine uses when the receiver advertises
// feature bit 72 (SupportsBufferedAPAP):
//   [time value, int64 BE][timescale, int32 BE][sequence number, uint24 BE]
//   [extensions: {UIntV type != 0, UIntV length, data}..., then UIntV 0][audio frame]
// UIntV is big-endian base 128 (every byte but the last has 0x80 set). Extension 2 is the audio
// format index (the classic buffered packets' SSRC top byte), 4 and 5 are trim durations.
//
// Over TCP (a buffered stream) each packet is preceded by its length, a uint32 BE that counts
// itself, and is encrypted with the stream key ("shk"): bytes 0..11 are authenticated, bytes 15
// on are encrypted, followed by a 16-byte tag and an 8-byte little-endian nonce.
//
// Over UDP (APAT, the low-latency stream) the APAP packets go as RTP ("APAP-RTP"), encrypted with
// the stream connection's DataStream key (the RTP header is authenticated, the rest encrypted,
// followed by the tag and the 8-byte nonce):
// - payload type 112: a whole packet. Its payload is [time value's high 32 bits, BE][timescale,
//   BE] and then the APAP body (extensions and frame); the RTP timestamp is the time value's low
//   32 bits.
// - 113, 114, 115: the first, middle and last fragments of a packet too long for one datagram:
//   consecutive sequence numbers, the same timestamp; their payloads joined are a 112 payload.
// - 121: RFC 2198 redundancy. The primary block (normally 112) and earlier packets (116: an APAP
//   body without the 8-byte prefix, which is that of the packet after it). The sender's
//   retransmissions have an SSRC ending in 0x0BAD.
// - RTCP XR (207) with a Discard RLE block (25): the sender's send window.
// The receiver answers with RFC 8888 congestion control feedback (CCFB).
// Keys: HKDF-SHA512 of the pair-setup shared secret, salt "DataStream-Salt" followed by the
// connection's seed in decimal, info "DataStream-Output-Encryption-Key" (sender to receiver) and
// "DataStream-Input-Encryption-Key" (receiver to sender).
//
// The functions here do no I/O and keep no state, so they can be tried on captured packets.

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define APAT_KEY_LENGTH 32
#define APAT_MAX_UNITS 8 // a RED packet's primary block and up to seven redundant ones
#define APAT_PREFIX_LENGTH 8
#define APAT_PAYLOAD_TYPE_WHOLE 112
#define APAT_PAYLOAD_TYPE_FIRST_FRAGMENT 113
#define APAT_PAYLOAD_TYPE_MIDDLE_FRAGMENT 114
#define APAT_PAYLOAD_TYPE_LAST_FRAGMENT 115
#define APAT_PAYLOAD_TYPE_REDUNDANT 116
#define APAT_PAYLOAD_TYPE_RED 121
#define APAT_RETRANSMISSION_SSRC 0x0BAD

// Derive one stream connection's keys. The "out" key decrypts what the sender sends; the "in" key
// encrypts what the receiver sends back.
void apat_derive_keys(const uint8_t *shared_secret, size_t shared_secret_length, uint64_t seed,
                      uint8_t out_key[APAT_KEY_LENGTH], uint8_t in_key[APAT_KEY_LENGTH]);

// An APAP body: its extensions and the audio frame after them.
typedef struct {
  int has_format_index;
  uint32_t format_index; // extension 2
  const uint8_t *frame;
  size_t frame_length;
} apap_body_t;

// Parse an APAP body. Returns 0, or -1 if it is malformed.
int apap_parse_body(const uint8_t *body, size_t length, apap_body_t *result);

// An APAP packet received over TCP, without its length prefix.
typedef struct {
  int64_t time_value;
  int32_t time_scale;
  uint32_t sequence_number; // 24 bits
  apap_body_t body;         // points into the caller's plaintext buffer
} apap_packet_t;

// Authenticate, decrypt and parse an APAP packet with the stream key. `plaintext` must hold at
// least `length` bytes. Returns 0, -1 if it is not authentic, or -2 if it is malformed.
int apap_open_packet(const uint8_t *packet, size_t length, const uint8_t key[APAT_KEY_LENGTH],
                     uint8_t *plaintext, size_t plaintext_size, apap_packet_t *result);

// One APAP-RTP packet ("unit") carried by a datagram.
typedef struct {
  uint8_t payload_type; // 112, 113, 114, 115 or 116
  uint16_t sequence_number;
  uint32_t timestamp;
  int redundant;       // from a redundant block of a RED packet
  const uint8_t *data; // the unit's payload, in the caller's plaintext buffer
  size_t length;
} apat_unit_t;

typedef enum {
  apat_datagram_unknown = 0,
  apat_datagram_rtp,
  apat_datagram_xr,
} apat_datagram_kind_t;

typedef struct {
  apat_datagram_kind_t kind;
  uint32_t ssrc;
  // RTP
  int retransmission; // the SSRC ends in 0x0BAD
  uint16_t sequence_number;
  uint32_t timestamp;
  int unit_count; // the primary (or only) unit first, then redundant ones, newest to oldest
  apat_unit_t units[APAT_MAX_UNITS];
  // XR: the sender's send window, from begin to (not including) end
  int has_window;
  uint16_t window_begin, window_end;
} apat_datagram_t;

// Authenticate, decrypt and parse a datagram from the sender. `plaintext` must hold at least
// `length` bytes. Returns 0, -1 if it is not authentic, or -2 if it is malformed or unknown.
int apat_open_datagram(const uint8_t *packet, size_t length, const uint8_t out_key[APAT_KEY_LENGTH],
                       uint8_t *plaintext, size_t plaintext_size, apat_datagram_t *result);

// A whole (112) unit's media time and APAP body. `prefix` is the 8-byte prefix to use for a 116
// unit (that of the unit after it); it is filled in from a 112 unit. Returns 0, or -1 if the
// unit is malformed.
int apat_unit_body(const apat_unit_t *unit, uint8_t prefix[APAT_PREFIX_LENGTH],
                   uint64_t *time_value, uint32_t *time_scale, apap_body_t *body);

// RFC 8888 metric block for a received packet: R = 1 and the arrival time offset, in 1/1024 s,
// before the report timestamp, or 0x1FFF for a packet without an arrival time (recovered from
// redundancy or retransmitted). A missing packet's metric block is 0.
uint16_t apat_ccfb_metric(uint64_t arrival_to_report_ns);
#define APAT_CCFB_METRIC_NO_ARRIVAL_TIME 0x9FFF

// The middle 32 bits of an NTP-format time for a time in nanoseconds (RFC 8888's report
// timestamp; any steady clock will do: the sender uses differences).
uint32_t apat_ntp_middle_32(uint64_t time_ns);

// Build an encrypted CCFB packet reporting `report_count` consecutive packets from `begin_seq`.
// `ccfb_index` counts the CCFB packets sent on this connection, starting at 0.
// Returns its length, or 0 if `out_size` is too small or the count is out of range (1 to 512).
#define APAT_CCFB_MAX_REPORTS 512
size_t apat_build_ccfb(uint8_t *out, size_t out_size, uint32_t media_ssrc, uint16_t begin_seq,
                       const uint16_t *metrics, int report_count, uint32_t report_timestamp,
                       uint64_t ccfb_index, const uint8_t in_key[APAT_KEY_LENGTH]);

// The 32-bit RTP time of a media time, value / scale seconds, at `rate` frames per second,
// rounded to the nearest frame.
uint32_t apat_media_time_to_rtp(uint64_t value, uint64_t scale, uint32_t rate);

// Reorder buffer. The player decodes each frame as it gets it, and AAC-ELD frames must be decoded
// in order, so frames are released strictly in timestamp order. When one is missing, the later
// ones are held until it arrives (from a redundant block or a retransmission) or the caller gives
// up on it, when its play time is too close.
#define APAT_REORDER_SLOTS 64 // 640 ms of AAC-ELD frames
#define APAT_MAX_ACCESS_UNIT_LENGTH 1536

typedef struct {
  int used;
  int recovered; // it came from a redundant block or a retransmission
  uint32_t timestamp;
  size_t length;
  uint8_t data[APAT_MAX_ACCESS_UNIT_LENGTH];
} apat_reorder_slot_t;

typedef struct {
  uint32_t frame_length; // frames per packet: one slot per packet
  int have_next;
  uint32_t base_timestamp; // slots are counted from here, so that the timestamps can wrap
  uint32_t next_timestamp; // of the next frame to release
  int held;
  apat_reorder_slot_t slots[APAT_REORDER_SLOTS];
} apat_reorder_t;

// Empty the buffer, for packets of `frame_length` frames.
void apat_reorder_reset(apat_reorder_t *reorder, uint32_t frame_length);

// Hold a frame. The first frame after a reset sets where release starts. Returns 1 if it was
// held, 0 if it is a duplicate or slightly older than the next frame to release, or -1 if it is
// too far ahead or behind to belong to the same run, in which case everything held is dropped and
// release restarts from it; a recovered frame that far off is dropped instead (0).
int apat_reorder_add(apat_reorder_t *reorder, uint32_t timestamp, const uint8_t *data,
                     size_t length, int recovered);

// True if frames are held but the next one to release is missing.
int apat_reorder_waiting(const apat_reorder_t *reorder);

// Release the next frame: the next one in order, if it's held, or, if `give_up` is true and it
// is missing, the earliest frame held after it. Returns NULL if there is nothing to release. The
// slot stays valid until the next call.
apat_reorder_slot_t *apat_reorder_release(apat_reorder_t *reorder, int give_up);

#endif // _AP2_APAT_CODEC_H

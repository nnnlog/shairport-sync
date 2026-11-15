/*
 * AirPlay 2 low-latency audio stream. This file is part of Shairport Sync.
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

#ifndef _AP2_APAT_H
#define _AP2_APAT_H

#include "player.h"
#include <plist/plist.h>

// The low-latency stream ("Realtime APAT"): a type 103 stream SETUP whose "streamConnections"
// ask for an APAT connection. The audio comes over UDP as APAP-RTP packets (see ap2_apat_codec.h)
// and goes to the player; the receiver answers with RFC 8888 feedback. The anchor time, pause and
// flush come as RTSP requests (SETRATEANCHORTIME, FLUSHBUFFERED), as for a buffered stream.

// Set up the low-latency stream for a stream SETUP: open its UDP port, start its threads (one for
// the network, one feeding the player) and add "streamConnections" to the reply's stream
// dictionary. While it plays, the player aims for a
// backend buffer of low_latency_audio_backend_buffer_desired_length.
// Returns 0, or -1 with nothing set up.
int ap2_apat_setup(rtsp_conn_info *conn, plist_t stream, plist_t reply_stream);

// Stop the low-latency stream, if there is one, and free it.
void ap2_apat_stop(rtsp_conn_info *conn);

// Give the calling thread of a low-latency stream an audio priority where real-time scheduling is
// refused: on Linux (and so Android, whose apps cannot have SCHED_FIFO) a negative nice value for
// this thread, as Android gives its own audio threads (THREAD_PRIORITY_AUDIO is -16,
// THREAD_PRIORITY_URGENT_AUDIO -19). Without the right to (RLIMIT_NICE, CAP_SYS_NICE), or on
// other systems, nothing changes.
void ap2_apat_audio_thread_priority(int nice_value);

#endif // _AP2_APAT_H

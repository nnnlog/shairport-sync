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

#include "ap2_apat_codec.h"

#include <inttypes.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>

#define RTP_HEADER_LENGTH 12
#define TAG_LENGTH 16       // ChaCha20-Poly1305
#define COUNTER_LENGTH 8    // the little-endian packet counter at the end, used as the nonce
#define RTCP_INDEX_LENGTH 4 // the E flag and index (SRTCP style) after an RTCP packet's ciphertext
#define RTCP_PACKET_TYPE_XR 207
#define RTCP_PACKET_TYPE_CCFB 205 // RTPFB, with format 11
#define CCFB_FORMAT 11
#define XR_BLOCK_TYPE_DISCARD_RLE 25
#define APAP_HEADER_LENGTH 15
#define APAP_AUTHENTICATED_LENGTH 12

static uint16_t get16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }

static uint32_t get32(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static uint64_t get64(const uint8_t *p) { return ((uint64_t)get32(p) << 32) | get32(p + 4); }

static void put16(uint8_t *p, uint16_t v) {
  p[0] = v >> 8;
  p[1] = v & 0xff;
}

static void put32(uint8_t *p, uint32_t v) {
  p[0] = v >> 24;
  p[1] = (v >> 16) & 0xff;
  p[2] = (v >> 8) & 0xff;
  p[3] = v & 0xff;
}

// the 12-byte nonce: four zero bytes and the 8-byte little-endian counter
static void make_nonce(uint8_t nonce[12], const uint8_t counter_le[COUNTER_LENGTH]) {
  memset(nonce, 0, 4);
  memcpy(nonce + 4, counter_le, COUNTER_LENGTH);
}

// RFC 5869 HKDF with HMAC-SHA512, for an output of up to 64 bytes (one block)
static void hkdf_sha512(uint8_t *out, size_t out_length, const uint8_t *ikm, size_t ikm_length,
                        const char *salt, const char *info) {
  uint8_t prk[crypto_auth_hmacsha512_BYTES];
  uint8_t block[crypto_auth_hmacsha512_BYTES];
  const uint8_t one = 1;
  crypto_auth_hmacsha512_state state;

  crypto_auth_hmacsha512_init(&state, (const unsigned char *)salt, strlen(salt));
  crypto_auth_hmacsha512_update(&state, ikm, ikm_length);
  crypto_auth_hmacsha512_final(&state, prk);

  crypto_auth_hmacsha512_init(&state, prk, sizeof(prk));
  crypto_auth_hmacsha512_update(&state, (const unsigned char *)info, strlen(info));
  crypto_auth_hmacsha512_update(&state, &one, 1);
  crypto_auth_hmacsha512_final(&state, block);

  memcpy(out, block, out_length < sizeof(block) ? out_length : sizeof(block));
  sodium_memzero(prk, sizeof(prk));
  sodium_memzero(block, sizeof(block));
  sodium_memzero(&state, sizeof(state));
}

void apat_derive_keys(const uint8_t *shared_secret, size_t shared_secret_length, uint64_t seed,
                      uint8_t out_key[APAT_KEY_LENGTH], uint8_t in_key[APAT_KEY_LENGTH]) {
  char salt[64];
  snprintf(salt, sizeof(salt), "DataStream-Salt%" PRIu64, seed);
  hkdf_sha512(out_key, APAT_KEY_LENGTH, shared_secret, shared_secret_length, salt,
              "DataStream-Output-Encryption-Key");
  hkdf_sha512(in_key, APAT_KEY_LENGTH, shared_secret, shared_secret_length, salt,
              "DataStream-Input-Encryption-Key");
}

// A UIntV: big-endian base 128, every byte but the last with 0x80 set. Returns the number of bytes
// read, or 0 if it doesn't fit in `length` or in 64 bits.
static size_t get_uintv(const uint8_t *p, size_t length, uint64_t *value) {
  uint64_t v = 0;
  size_t i;
  for (i = 0; (i < length) && (i < 10); i++) {
    v = (v << 7) | (p[i] & 0x7F);
    if ((p[i] & 0x80) == 0) {
      *value = v;
      return i + 1;
    }
  }
  return 0;
}

int apap_parse_body(const uint8_t *body, size_t length, apap_body_t *result) {
  memset(result, 0, sizeof(apap_body_t));
  size_t i = 0;
  while (1) {
    uint64_t type, item_length;
    size_t n = get_uintv(body + i, length - i, &type);
    if (n == 0)
      return -1;
    i += n;
    if (type == 0)
      break; // the end of the extensions
    n = get_uintv(body + i, length - i, &item_length);
    if ((n == 0) || (item_length > length - i - n))
      return -1;
    i += n;
    if ((type == 2) && (item_length >= 1) && (item_length <= 4)) { // the audio format index
      uint32_t index = 0;
      size_t k;
      for (k = 0; k < item_length; k++)
        index = (index << 8) | body[i + k];
      result->has_format_index = 1;
      result->format_index = index;
    }
    i += item_length; // anything else isn't needed here
  }
  result->frame = body + i;
  result->frame_length = length - i;
  return 0;
}

int apap_open_packet(const uint8_t *packet, size_t length, const uint8_t key[APAT_KEY_LENGTH],
                     uint8_t *plaintext, size_t plaintext_size, apap_packet_t *result) {
  memset(result, 0, sizeof(apap_packet_t));
  if ((length < APAP_HEADER_LENGTH + 1 + TAG_LENGTH + COUNTER_LENGTH) || (plaintext_size < length))
    return -2;
  result->time_value = (int64_t)get64(packet);
  result->time_scale = (int32_t)get32(packet + 8);
  result->sequence_number = ((uint32_t)packet[12] << 16) | ((uint32_t)packet[13] << 8) | packet[14];
  uint8_t nonce[12];
  make_nonce(nonce, packet + length - COUNTER_LENGTH);
  unsigned long long plaintext_length = 0;
  if (crypto_aead_chacha20poly1305_ietf_decrypt(
          plaintext, &plaintext_length, NULL, packet + APAP_HEADER_LENGTH,
          length - APAP_HEADER_LENGTH - COUNTER_LENGTH, packet, APAP_AUTHENTICATED_LENGTH, nonce,
          key) != 0)
    return -1;
  if ((result->time_scale <= 0) ||
      (apap_parse_body(plaintext, (size_t)plaintext_length, &result->body) != 0))
    return -2;
  return 0;
}

static int add_unit(apat_datagram_t *result, uint8_t payload_type, uint16_t sequence_number,
                    uint32_t timestamp, int redundant, const uint8_t *data, size_t length) {
  if (result->unit_count >= APAT_MAX_UNITS)
    return -1;
  apat_unit_t *unit = &result->units[result->unit_count++];
  unit->payload_type = payload_type;
  unit->sequence_number = sequence_number;
  unit->timestamp = timestamp;
  unit->redundant = redundant;
  unit->data = data;
  unit->length = length;
  return 0;
}

// RFC 2198, split as Apple's receiver does it: four-byte headers for the redundant blocks
// (F = 1, block payload type, timestamp offset, block length), a one-byte header for the primary
// block (F = 0, payload type), then the redundant blocks' data and the primary block's. The
// primary block is the RTP packet's own; the redundant blocks are earlier packets: going back from
// the last header, each one's sequence number is one less than the one after it.
static int split_redundancy(const uint8_t *plaintext, size_t length, apat_datagram_t *result) {
  uint32_t headers[APAT_MAX_UNITS];
  int redundant_blocks = 0;
  size_t i = 0;
  size_t data_length = 0;
  while ((i < length) && ((plaintext[i] & 0x80) != 0)) {
    if ((i + 4 > length) || (redundant_blocks == APAT_MAX_UNITS - 1))
      return -2;
    headers[redundant_blocks] = get32(plaintext + i);
    data_length += headers[redundant_blocks] & 0x3FF;
    redundant_blocks++;
    i += 4;
  }
  if (i >= length)
    return -2;
  uint8_t primary_type = plaintext[i] & 0x7F;
  i++;
  if (i + data_length > length)
    return -2;
  // the primary block is after all the redundant blocks' data
  size_t primary_start = i + data_length;
  if (add_unit(result, primary_type, result->sequence_number, result->timestamp, 0,
               plaintext + primary_start, length - primary_start) != 0)
    return -2;
  size_t end = primary_start; // the end of the block being taken, going backwards
  uint16_t sequence_number = result->sequence_number;
  int b;
  for (b = redundant_blocks - 1; b >= 0; b--) {
    size_t block_length = headers[b] & 0x3FF;
    uint32_t offset = (headers[b] >> 10) & 0x3FFF;
    uint8_t type = (headers[b] >> 24) & 0x7F;
    sequence_number--;
    end -= block_length;
    if (block_length != 0)
      add_unit(result, type, sequence_number, result->timestamp - offset, 1, plaintext + end,
               block_length);
  }
  return 0;
}

int apat_open_datagram(const uint8_t *packet, size_t length, const uint8_t out_key[APAT_KEY_LENGTH],
                       uint8_t *plaintext, size_t plaintext_size, apat_datagram_t *result) {
  memset(result, 0, sizeof(apat_datagram_t));
  if ((length < 8) || ((packet[0] & 0xC0) != 0x80) || (plaintext_size < length)) // version 2
    return -2;
  uint8_t nonce[12];

  if (packet[1] == RTCP_PACKET_TYPE_XR) {
    // [header 8, clear][ciphertext][E and index 4][tag 16][counter 8]
    size_t rtcp_length = ((size_t)get16(packet + 2) + 1) * 4;
    if ((rtcp_length < 8) || (length < rtcp_length + RTCP_INDEX_LENGTH + TAG_LENGTH + COUNTER_LENGTH))
      return -2;
    uint8_t additional_data[8 + RTCP_INDEX_LENGTH];
    memcpy(additional_data, packet, 8);
    memcpy(additional_data + 8, packet + rtcp_length, RTCP_INDEX_LENGTH);
    make_nonce(nonce, packet + rtcp_length + RTCP_INDEX_LENGTH + TAG_LENGTH);
    result->kind = apat_datagram_xr;
    result->ssrc = get32(packet + 4);
    if (crypto_aead_chacha20poly1305_ietf_decrypt_detached(
            plaintext, NULL, packet + 8, rtcp_length - 8,
            packet + rtcp_length + RTCP_INDEX_LENGTH, additional_data, sizeof(additional_data),
            nonce, out_key) != 0)
      return -1;
    // report blocks: [type][type-specific][length in 32-bit words, less one]; a Discard RLE
    // block (RFC 7097) then has the media SSRC, begin_seq and end_seq (not included)
    size_t i = 0, blocks_length = rtcp_length - 8;
    while (i + 4 <= blocks_length) {
      size_t block_length = ((size_t)get16(plaintext + i + 2) + 1) * 4;
      if (i + block_length > blocks_length)
        break;
      if ((plaintext[i] == XR_BLOCK_TYPE_DISCARD_RLE) && (block_length >= 12)) {
        result->has_window = 1;
        result->window_begin = get16(plaintext + i + 8);
        result->window_end = get16(plaintext + i + 10);
      }
      i += block_length;
    }
    return 0;
  }

  uint8_t payload_type = packet[1] & 0x7F;
  if (((payload_type < APAT_PAYLOAD_TYPE_WHOLE) || (payload_type > APAT_PAYLOAD_TYPE_REDUNDANT)) &&
      (payload_type != APAT_PAYLOAD_TYPE_RED))
    return -2;
  if ((length < RTP_HEADER_LENGTH + TAG_LENGTH + COUNTER_LENGTH + 1) ||
      ((packet[0] & 0x3F) != 0)) // no padding, extension or CSRCs
    return -2;
  result->kind = apat_datagram_rtp;
  result->sequence_number = get16(packet + 2);
  result->timestamp = get32(packet + 4);
  result->ssrc = get32(packet + 8);
  result->retransmission = (result->ssrc & 0xFFFF) == APAT_RETRANSMISSION_SSRC;
  unsigned long long plaintext_length = 0;
  make_nonce(nonce, packet + length - COUNTER_LENGTH);
  if (crypto_aead_chacha20poly1305_ietf_decrypt(
          plaintext, &plaintext_length, NULL, packet + RTP_HEADER_LENGTH,
          length - RTP_HEADER_LENGTH - COUNTER_LENGTH, packet, RTP_HEADER_LENGTH, nonce,
          out_key) != 0)
    return -1;
  if (payload_type == APAT_PAYLOAD_TYPE_RED)
    return split_redundancy(plaintext, (size_t)plaintext_length, result);
  add_unit(result, payload_type, result->sequence_number, result->timestamp, 0, plaintext,
           (size_t)plaintext_length);
  return 0;
}

int apat_unit_body(const apat_unit_t *unit, uint8_t prefix[APAT_PREFIX_LENGTH],
                   uint64_t *time_value, uint32_t *time_scale, apap_body_t *body) {
  const uint8_t *data = unit->data;
  size_t length = unit->length;
  if (unit->payload_type == APAT_PAYLOAD_TYPE_WHOLE) {
    if (length < APAT_PREFIX_LENGTH)
      return -1;
    memcpy(prefix, data, APAT_PREFIX_LENGTH);
    data += APAT_PREFIX_LENGTH;
    length -= APAT_PREFIX_LENGTH;
  } else if (unit->payload_type != APAT_PAYLOAD_TYPE_REDUNDANT) {
    return -1;
  }
  *time_scale = get32(prefix + 4);
  if (*time_scale == 0)
    return -1; // no prefix yet
  *time_value = ((uint64_t)get32(prefix) << 32) | unit->timestamp;
  return apap_parse_body(data, length, body);
}

uint32_t apat_ntp_middle_32(uint64_t time_ns) {
  uint64_t seconds = time_ns / 1000000000;
  uint64_t fraction = ((time_ns % 1000000000) << 32) / 1000000000;
  return (uint32_t)(((seconds & 0xFFFF) << 16) | (fraction >> 16));
}

uint16_t apat_ccfb_metric(uint64_t arrival_to_report_ns) {
  uint64_t offset = (arrival_to_report_ns * 1024) / 1000000000; // in 1/1024 s
  if (offset > 0x1FFE)
    offset = 0x1FFE; // 0x1FFF means "no arrival time"
  return (uint16_t)(0x8000 | offset); // R = 1, ECN = 0
}

size_t apat_build_ccfb(uint8_t *out, size_t out_size, uint32_t media_ssrc, uint16_t begin_seq,
                       const uint16_t *metrics, int report_count, uint32_t report_timestamp,
                       uint64_t ccfb_index, const uint8_t in_key[APAT_KEY_LENGTH]) {
  if ((report_count < 1) || (report_count > APAT_CCFB_MAX_REPORTS))
    return 0;
  // header 8, media SSRC 4, begin_seq and num_reports 4, metric blocks padded to 32 bits, report
  // timestamp 4
  size_t rtcp_length = 8 + 4 + 4 + (((size_t)report_count * 2 + 3) & ~(size_t)3) + 4;
  size_t total_length = rtcp_length + RTCP_INDEX_LENGTH + TAG_LENGTH + COUNTER_LENGTH;
  if (out_size < total_length)
    return 0;

  uint8_t packet[8 + 4 + 4 + APAT_CCFB_MAX_REPORTS * 2 + 4];
  memset(packet, 0, rtcp_length);
  packet[0] = 0x80 | CCFB_FORMAT;
  packet[1] = RTCP_PACKET_TYPE_CCFB;
  put16(packet + 2, (uint16_t)(rtcp_length / 4 - 1));
  // Apple's receiver: the reporting SSRC is the media SSRC's high half and 0x0BAC
  put32(packet + 4, (media_ssrc & 0xFFFF0000) | 0x0BAC);
  put32(packet + 8, media_ssrc & 0xFFFF0000);
  put16(packet + 12, begin_seq);
  put16(packet + 14, (uint16_t)report_count);
  int i;
  for (i = 0; i < report_count; i++)
    put16(packet + 16 + 2 * i, metrics[i]);
  put32(packet + rtcp_length - 4, report_timestamp);

  uint32_t e_and_index = 0x80000000 | (uint32_t)(ccfb_index & 0x7FFFFFFF);
  uint8_t counter[COUNTER_LENGTH];
  for (i = 0; i < COUNTER_LENGTH; i++)
    counter[i] = (ccfb_index >> (8 * i)) & 0xff;
  uint8_t nonce[12];
  make_nonce(nonce, counter);
  uint8_t additional_data[8 + RTCP_INDEX_LENGTH];
  memcpy(additional_data, packet, 8);
  put32(additional_data + 8, e_and_index);

  memcpy(out, packet, 8);
  crypto_aead_chacha20poly1305_ietf_encrypt_detached(
      out + 8, out + rtcp_length + RTCP_INDEX_LENGTH, NULL, packet + 8, rtcp_length - 8,
      additional_data, sizeof(additional_data), NULL, nonce, in_key);
  put32(out + rtcp_length, e_and_index);
  memcpy(out + rtcp_length + RTCP_INDEX_LENGTH + TAG_LENGTH, counter, COUNTER_LENGTH);
  return total_length;
}

uint32_t apat_media_time_to_rtp(uint64_t value, uint64_t scale, uint32_t rate) {
  if (scale == 0)
    return 0;
  // split the division so that nothing overflows for any likely scale; wrapping in the whole
  // seconds part doesn't matter, as only the low 32 bits are wanted. Rounded to the nearest
  // frame, so that a time in a finer scale (e.g. nanoseconds) gives the exact frame.
  uint64_t whole = (value / scale) * rate;
  uint64_t remainder = value % scale;
  uint64_t part;
  if (remainder <= (UINT64_MAX - scale / 2) / rate)
    part = (remainder * rate + scale / 2) / scale;
  else
    part = (uint64_t)(((long double)remainder * rate) / scale + 0.5L);
  return (uint32_t)(whole + part);
}

void apat_reorder_reset(apat_reorder_t *reorder, uint32_t frame_length) {
  int i;
  for (i = 0; i < APAT_REORDER_SLOTS; i++)
    reorder->slots[i].used = 0;
  reorder->frame_length = frame_length ? frame_length : 480;
  reorder->have_next = 0;
  reorder->held = 0;
}

static int reorder_index(const apat_reorder_t *reorder, uint32_t timestamp) {
  return ((uint32_t)(timestamp - reorder->base_timestamp) / reorder->frame_length) %
         APAT_REORDER_SLOTS;
}

static void reorder_start(apat_reorder_t *reorder, uint32_t timestamp) {
  reorder->have_next = 1;
  reorder->base_timestamp = timestamp;
  reorder->next_timestamp = timestamp;
}

int apat_reorder_add(apat_reorder_t *reorder, uint32_t timestamp, const uint8_t *data,
                     size_t length, int recovered) {
  if (length > APAT_MAX_ACCESS_UNIT_LENGTH)
    return 0;
  int response = 1;
  if (reorder->have_next == 0) {
    reorder_start(reorder, timestamp);
  } else {
    int32_t ahead = (int32_t)(timestamp - reorder->next_timestamp);
    int32_t span = (int32_t)(APAT_REORDER_SLOTS * reorder->frame_length);
    if ((ahead < 0) && (ahead >= -span))
      return 0; // already released or given up on: a late copy
    if ((ahead >= span) || (ahead < -span)) {
      // a different run of timestamps: the sender has restarted its timeline. Only a frame as
      // sent can say so: a stale copy (from redundancy or a retransmission) is dropped.
      if (recovered != 0)
        return 0;
      apat_reorder_reset(reorder, reorder->frame_length);
      reorder_start(reorder, timestamp);
      response = -1;
    }
  }
  apat_reorder_slot_t *slot = &reorder->slots[reorder_index(reorder, timestamp)];
  if ((slot->used != 0) && (slot->timestamp == timestamp))
    return 0; // a duplicate
  if (slot->used == 0)
    reorder->held++;
  slot->used = 1;
  slot->recovered = recovered;
  slot->timestamp = timestamp;
  slot->length = length;
  memcpy(slot->data, data, length);
  return response;
}

int apat_reorder_waiting(const apat_reorder_t *reorder) {
  if ((reorder->have_next == 0) || (reorder->held == 0))
    return 0;
  const apat_reorder_slot_t *slot =
      &reorder->slots[reorder_index(reorder, reorder->next_timestamp)];
  return (slot->used == 0) || (slot->timestamp != reorder->next_timestamp);
}

apat_reorder_slot_t *apat_reorder_release(apat_reorder_t *reorder, int give_up) {
  if ((reorder->have_next == 0) || (reorder->held == 0))
    return NULL;
  apat_reorder_slot_t *slot = &reorder->slots[reorder_index(reorder, reorder->next_timestamp)];
  if ((slot->used == 0) || (slot->timestamp != reorder->next_timestamp)) {
    if (give_up == 0)
      return NULL;
    // find the earliest frame held after the missing one
    apat_reorder_slot_t *earliest = NULL;
    int i;
    for (i = 0; i < APAT_REORDER_SLOTS; i++) {
      apat_reorder_slot_t *candidate = &reorder->slots[i];
      if ((candidate->used != 0) &&
          ((earliest == NULL) || ((int32_t)(candidate->timestamp - earliest->timestamp) < 0)))
        earliest = candidate;
    }
    if (earliest == NULL)
      return NULL;
    slot = earliest;
  }
  slot->used = 0;
  reorder->held--;
  reorder->next_timestamp = slot->timestamp + reorder->frame_length;
  return slot;
}

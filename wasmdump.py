#!/usr/bin/env python3

import argparse
import codecs
import sys
from struct import unpack

# -----------------------------------------------------------------------------

LINE_SEP = '-' * 78

ADRFMT = None
BYTESW = 8
LEFTW = BYTESW * 3 - 1
LPAD = None


# -----------------------------------------------------------------------------


def dprint(data, message):
    left = []
    if data is not None:
        addr = data.fpos
        left = [
            ((ADRFMT % (addr + p)) + ' ' +
             ' '.join(f'{d:02x}' for d in data[p:p+BYTESW]) + LPAD)[:LEFTW]
            for p in range(0, len(data), BYTESW)
        ]
    right = [message] if isinstance(message, str) else message
    diff = len(right) - len(left)
    left += [LPAD] * max(0, diff)
    right += [''] * max(0, -diff)
    for pos, llin in enumerate(left):
        print(llin + ' | ' + right[pos])


# -----------------------------------------------------------------------------


def data_string(data):
    return ''.join(chr(c) if c in range(0x20, 0x7F) else '.' for c in data)


def data_strings(data, indent=''):
    return [f'{indent}"{data_string(data[p:p+BYTESW])}"' for p in range(0, len(data), BYTESW)]


def decode_leb128u(data):
    return sum((v & 0x7f) << (n * 7) for n, v in enumerate(data))


def decode_leb128s(data):
    val = decode_leb128u(data)
    return val - (1 << (len(data) * 7)) if data[-1] & 0x40 else val


class ValueData:
    def __init__(self, value, data):
        self.value = value
        self.data = data


class Integer(ValueData):
    def __init__(self, value, data):
        super().__init__(value, data)

    def __int__(self):
        return self.value


class String(ValueData):
    def __init__(self, value, data):
        super().__init__(value, data)

    def __str__(self):
        return self.value


class List(ValueData):
    def __init__(self, value, data):
        super().__init__(value, data)

    def __len__(self):
        return len(self.data)

    def __getitem__(self, key):
        return self.data[key]


class ReadData:
    def __init__(self, path, data, fpos):
        self.path = path
        self.data = data
        self.fpos = fpos
        self.rpos = 0

    def __len__(self):
        return len(self.data)

    def __getitem__(self, key):
        return self.data[key]

    def remain(self):
        return len(self.data) - self.rpos

    def read(self, size):
        fpos = self.fpos + self.rpos
        data = self.data[self.rpos:self.rpos + size]
        self.rpos += len(data)
        return ReadData(self.path, data, fpos)

    def load(self, size):
        data = self.read(size)
        if len(data) != size:
            raise IOError(f'not enough data: {self.path}')
        return data

    def reload(self, rpos):
        rlen = self.rpos - rpos
        self.rpos = rpos
        return self.load(rlen)

    def byte(self):
        data = self.load(1)
        return Integer(data[0], data)

    def long(self):
        data = self.read(4)
        u32 = data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24)
        return Integer(u32, data)

    def leb128(self):
        dat = self.data
        pos = self.rpos
        val = 0x80
        while val & 0x80:
            val = dat[pos]
            pos += 1
        return self.read(pos - self.rpos)

    def leb128u(self):
        dat = self.leb128()
        return Integer(decode_leb128u(dat), dat)

    def leb128s(self):
        dat = self.leb128()
        return Integer(decode_leb128s(dat), dat)

    def utf8(self):
        cnt = self.leb128u()
        utf8 = self.load(int(cnt))
        cnt.data.data += utf8.data
        return String(codecs.decode(utf8.data), cnt.data)


# -----------------------------------------------------------------------------


NUMTYPE = {
    0x7F: 'i32',
    0x7E: 'i64',
    0x7D: 'f32',
    0x7C: 'f64',
}
VECTYPE = {
    0x7B: 'v128',
}
REFTYPE = {
    0x70: 'funcref',
    0x6F: 'externref',
}
VALTYPE = NUMTYPE | VECTYPE | REFTYPE

FUNCTYPE = {
    0x60: 'functype',
}

MUTABILITY = {
    0: 'const',
    1: 'var',
}

IMPORT_MODE = {
    0: 'func',
    1: 'table',
    2: 'mem',
    3: 'global',
}
EXPORT_MODE = IMPORT_MODE


def get_valtype(code):
    return VALTYPE.get(code, f'(valtype:0x{code:02x})')


def get_reftype(code):
    return REFTYPE.get(code, f'(reftype:0x{code:02x})')


def reference_type(stream, prefix=''):
    code = stream.leb128u()
    name = REFTYPE.get(int(code))
    dprint(code.data, f'{prefix}{name}')
    if name is None:
        raise NotImplementedError(f'unknown reftype: 0x{int(code):02x}')


def value_type(stream, prefix=''):
    code = stream.byte()
    name = VALTYPE.get(int(code))
    dprint(code.data, f'{prefix}{name}')
    if name is None:
        raise NotImplementedError(f'unknown valtype: 0x{int(code):02x}')


def result_type(stream, name, prefix=''):
    vsiz = stream.leb128u()
    vlen = int(vsiz)
    dprint(vsiz.data, f'{prefix}{name}[{vlen}]')
    for _ in range(vlen):
        value_type(stream, f'{prefix}  ')


def limits(stream, prefix=''):
    code = stream.byte()
    mode = int(code)
    dprint(code.data, f'{prefix}limits')
    if mode >= 2:
        raise NotImplementedError(f'unknown limits: 0x{mode}:02x')
    lmin = stream.leb128u()
    dprint(lmin.data, f'{prefix}  min = {int(lmin)}')
    if mode == 1:
        lmax = stream.leb128u()
        dprint(lmax.data, f'{prefix}  max = {int(lmax)}')


def mutability(stream, prefix=''):
    code = stream.byte()
    mode = int(code)
    name = MUTABILITY.get(mode)
    dprint(code.data, f'{prefix}{name}')
    if name is None:
        raise NotImplementedError(f'unknown mutability: {mode}')


# -----------------------------------------------------------------------------


DISASM = [
    # 0x00
    [[], ['unreachable']],
    [[], ['nop']],
    [['bt'], ['block', 'bt']],
    [['bt'], ['loop', 'bt']],
    [['bt'], ['if', 'bt']],
    [[], ['else']],
    [],[],[],[],[],
    [[], ['end']],
    [['lid'], ['br', 'lid']],
    [['lid'], ['br_if', 'lid']],
    [['lid+'], ['br_table', 'lid+']],
    [[], ['return']],
    # 0x10
    [['fid'], ['call', 'fid']],
    [['xid', 'tid'], ['call_indirect', 'xid', 'tid']],
    [],[],[],[],[],[],[],[],
    [[], ['drop']],
    [[], ['select']],
    [['t+'], ['select', 't+']],
    [],[],[],
    # 0x20
    [['lid'], ['local.get', 'lid']],
    [['lid'], ['local.set', 'lid']],
    [['lid'], ['local.tee', 'lid']],
    [['gid'], ['global.get', 'gid']],
    [['gid'], ['global.set', 'gid']],
    [['tid'], ['table.get', 'tid']],
    [['tid'], ['table.set', 'tid']],
    [],
    [['mao'], ['i32.load', 'mao']],
    [['mao'], ['i64.load', 'mao']],
    [['mao'], ['f32.load', 'mao']],
    [['mao'], ['f64.load', 'mao']],
    [['mao'], ['i32.load8_s', 'mao']],
    [['mao'], ['i32.load8_u', 'mao']],
    [['mao'], ['i32.load16_s', 'mao']],
    [['mao'], ['i32.load16_u', 'mao']],
    # 0x30
    [['mao'], ['i64.load8_s', 'mao']],
    [['mao'], ['i64.load8_u', 'mao']],
    [['mao'], ['i64.load16_s', 'mao']],
    [['mao'], ['i64.load16_u', 'mao']],
    [['mao'], ['i64.load32_s', 'mao']],
    [['mao'], ['i64.load32_u', 'mao']],
    [['mao'], ['i32.store', 'mao']],
    [['mao'], ['i64.store', 'mao']],
    [['mao'], ['f32.store', 'mao']],
    [['mao'], ['f64.store', 'mao']],
    [['mao'], ['i32.store8', 'mao']],
    [['mao'], ['i32.store16', 'mao']],
    [['mao'], ['i64.store8', 'mao']],
    [['mao'], ['i64.store16', 'mao']],
    [['mao'], ['i64.store32', 'mao']],
    [[0], ['memory.size']],
    # 0x40
    [[0], ['memory.grow']],
    [['i32'], ['i32.const', 'i32']],
    [['i64'], ['i64.const', 'i64']],
    [['f32'], ['f32.const', 'f32']],
    [['f64'], ['f64.const', 'f64']],
    [[], ['i32.eqz']],
    [[], ['i32.eq']],
    [[], ['i32.ne']],
    [[], ['i32.lt_s']],
    [[], ['i32.lt_u']],
    [[], ['i32.gt_s']],
    [[], ['i32.gt_u']],
    [[], ['i32.le_s']],
    [[], ['i32.le_u']],
    [[], ['i32.ge_s']],
    [[], ['i32.ge_u']],
    # 0x50
    [[], ['i64.eqz']],
    [[], ['i64.eq']],
    [[], ['i64.ne']],
    [[], ['i64.lt_s']],
    [[], ['i64.lt_u']],
    [[], ['i64.gt_s']],
    [[], ['i64.gt_u']],
    [[], ['i64.le_s']],
    [[], ['i64.le_u']],
    [[], ['i64.ge_s']],
    [[], ['i64.ge_u']],
    [[], ['f32.eq']],
    [[], ['f32.ne']],
    [[], ['f32.lt']],
    [[], ['f32.gt']],
    [[], ['f32.le']],
    # 0x60
    [[], ['f32.ge']],
    [[], ['f64.eq']],
    [[], ['f64.ne']],
    [[], ['f64.lt']],
    [[], ['f64.gt']],
    [[], ['f64.le']],
    [[], ['f64.ge']],
    [[], ['i32.clz']],
    [[], ['i32.ctz']],
    [[], ['i32.popcnt']],
    [[], ['i32.add']],
    [[], ['i32.sub']],
    [[], ['i32.mul']],
    [[], ['i32.div_s']],
    [[], ['i32.div_u']],
    [[], ['i32.rem_s']],
    # 0x70
    [[], ['i32.rem_u']],
    [[], ['i32.and']],
    [[], ['i32.or']],
    [[], ['i32.xor']],
    [[], ['i32.shl']],
    [[], ['i32.shr_s']],
    [[], ['i32.shr_u']],
    [[], ['i32.rotl']],
    [[], ['i32.rotr']],
    [[], ['i64.clz']],
    [[], ['i64.ctz']],
    [[], ['i64.popcnt']],
    [[], ['i64.add']],
    [[], ['i64.sub']],
    [[], ['i64.mul']],
    [[], ['i64.div_s']],
    # 0x80
    [[], ['i64.div_u']],
    [[], ['i64.rem_s']],
    [[], ['i64.rem_u']],
    [[], ['i64.and']],
    [[], ['i64.or']],
    [[], ['i64.xor']],
    [[], ['i64.shl']],
    [[], ['i64.shr_s']],
    [[], ['i64.shr_u']],
    [[], ['i64.rotl']],
    [[], ['i64.rotr']],
    [[], ['f32.abs']],
    [[], ['f32.neg']],
    [[], ['f32.ceil']],
    [[], ['f32.floor']],
    [[], ['f32.trunc']],
    # 0x90
    [[], ['f32.nearest']],
    [[], ['f32.sqrt']],
    [[], ['f32.add']],
    [[], ['f32.sub']],
    [[], ['f32.mul']],
    [[], ['f32.div']],
    [[], ['f32.min']],
    [[], ['f32.max']],
    [[], ['f32.copysign']],
    [[], ['f64.abs']],
    [[], ['f64.neg']],
    [[], ['f64.ceil']],
    [[], ['f64.floor']],
    [[], ['f64.trunc']],
    [[], ['f64.nearest']],
    [[], ['f64.sqrt']],
    # 0xA0
    [[], ['f64.add']],
    [[], ['f64.sub']],
    [[], ['f64.mul']],
    [[], ['f64.div']],
    [[], ['f64.min']],
    [[], ['f64.max']],
    [[], ['f64.copysign']],
    [[], ['i32.wrap']],
    [[], ['i32.trunc_f32_s']],
    [[], ['i32.trunc_f32_u']],
    [[], ['i32.trunc_f64_s']],
    [[], ['i32.trunc_f64_u']],
    [[], ['i64.extend_i32_s']],
    [[], ['i64.extend_i32_u']],
    [[], ['i64.trunc_f32_s']],
    [[], ['i64.trunc_f32_u']],
    # 0xB0
    [[], ['i64.trunc_f64_s']],
    [[], ['i64.trunc_f64_u']],
    [[], ['f32.convert_i32_s']],
    [[], ['f32.convert_i32_u']],
    [[], ['f32.convert_i64_s']],
    [[], ['f32.convert_i64_u']],
    [[], ['f32.demote_f64']],
    [[], ['f64.convert_i32_s']],
    [[], ['f64.convert_i32_u']],
    [[], ['f64.convert_i64_s']],
    [[], ['f64.convert_i64_u']],
    [[], ['f64.promote_f32']],
    [[], ['i32.reinterpret_f32']],
    [[], ['i64.reinterpret_f64']],
    [[], ['f32.reinterpret_i32']],
    [[], ['f64.reinterpret_i64']],
    # 0xC0
    [[], ['i32.extend8_s']],
    [[], ['i32.extend16_s']],
    [[], ['i64.extend8_s']],
    [[], ['i64.extend16_s']],
    [[], ['i64.extend32_s']],
    [],[],[],[],[],[],[],[],[],[],[],
    # 0xD0
    [['ref'], ['ref.null', 'ref']],
    [[], ['ref.is_null']],
    [['fid'], ['ref.func', 'fid']],
    [],[],[],[],[],[],[],[],[],[],[],[],[],
    # 0xE0
    [],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],
    # 0xF0
    [],[],[],[],[],[],[],[],[],[],[],[],
    [
        # 0x00
        [[], ['i32.trunc_sat_f32_s']],
        [[], ['i32.trunc_sat_f32_u']],
        [[], ['i32.trunc_sat_f64_s']],
        [[], ['i32.trunc_sat_f64_u']],
        [[], ['i64.trunc_sat_f32_s']],
        [[], ['i64.trunc_sat_f32_u']],
        [[], ['i64.trunc_sat_f64_s']],
        [[], ['i64.trunc_sat_f64_u']],
        [['eid', 0], ['memory.init', 'eid']],
        [['did'], ['data.drop', 'did']],
        [[0, 0], ['memory.copy']],
        [[0], ['memory.fill']],
        [['eid', 'tid'], ['table.init', 'eid', 'tid']],
        [['mid'], ['elem.drop', 'mid']],
        [['tid1', 'tid2'], ['table.copy', 'tid1', 'tid2']],
        [['tid'], ['table.grow', 'tid']],
        # 0x10
        [['tid'], ['table.size', 'tid']],
        [['tid'], ['table.fill', 'tid']],
        [],[],[],[],[],[],[],[],[],[],[],[],[],[],
        # 0x20
        [],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],
        # 0x30
        [],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],
        # 0x40
        [],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],
        # 0x50
        [],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],
        # 0x60
        [],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],
        # 0x70
        [],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],
        # 0x80
        [],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],
        # 0x90
        [],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],
        # 0xA0
        [],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],
        # 0xB0
        [],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],
        # 0xC0
        [],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],
        # 0xD0
        [],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],
        # 0xE0
        [],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],
        # 0xF0
        [],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],
    ],
    [
        # 0x00
        [['mao'], ['v128.load', 'mao']],
        [['mao'], ['v128.load8x8_s', 'mao']],
        [['mao'], ['v128.load8x8_u', 'mao']],
        [['mao'], ['v128.load16x4_s', 'mao']],
        [['mao'], ['v128.load16x4_u', 'mao']],
        [['mao'], ['v128.load32x2_s', 'mao']],
        [['mao'], ['v128.load32x2_u', 'mao']],
        [['mao'], ['v128.load8_splat', 'mao']],
        [['mao'], ['v128.load16_splat', 'mao']],
        [['mao'], ['v128.load32_splat', 'mao']],
        [['mao'], ['v128.load64_splat', 'mao']],
        [['mao'], ['v128.store', 'mao']],
        [['vb16'], ['v128.const', 'vb16']],
        [['vlt'], ['i8x16.shuffle', 'vlt']],
        [[], ['i8x16.swizzle']],
        [[], ['i8x16.splat']],
        # 0x10
        [[], ['i16x8.splat']],
        [[], ['i32x4.splat']],
        [[], ['i64x2.splat']],
        [[], ['f32x4.splat']],
        [[], ['f64x2.splat']],
        [['vl'], ['i8x16.extract_lane_s', 'vl']],
        [['vl'], ['i8x16.extract_lane_u', 'vl']],
        [['vl'], ['i8x16.replace_lane', 'vl']],
        [['vl'], ['i16x8.extract_lane_s', 'vl']],
        [['vl'], ['i16x8.extract_lane_u', 'vl']],
        [['vl'], ['i16x8.replace_lane', 'vl']],
        [['vl'], ['i32x4.extract_lane', 'vl']],
        [['vl'], ['i32x4.replace_lane', 'vl']],
        [['vl'], ['i64x2.extract_lane', 'vl']],
        [['vl'], ['i64x2.replace_lane', 'vl']],
        [['vl'], ['f32x4.extract_lane', 'vl']],
        # 0x20
        [['vl'], ['f32x4.replace_lane', 'vl']],
        [['vl'], ['f64x2.extract_lane', 'vl']],
        [['vl'], ['f64x2.replace_lane', 'vl']],
        [[], ['i8x16.eq']],
        [[], ['i8x16.ne']],
        [[], ['i8x16.lt_s']],
        [[], ['i8x16.lt_u']],
        [[], ['i8x16.gt_s']],
        [[], ['i8x16.gt_u']],
        [[], ['i8x16.le_s']],
        [[], ['i8x16.le_u']],
        [[], ['i8x16.ge_s']],
        [[], ['i8x16.ge_u']],
        [[], ['i16x8.eq']],
        [[], ['i16x8.ne']],
        [[], ['i16x8.lt_s']],
        # 0x30
        [[], ['i16x8.lt_u']],
        [[], ['i16x8.gt_s']],
        [[], ['i16x8.gt_u']],
        [[], ['i16x8.le_s']],
        [[], ['i16x8.le_u']],
        [[], ['i16x8.ge_s']],
        [[], ['i16x8.ge_u']],
        [[], ['i32x4.eq']],
        [[], ['i32x4.ne']],
        [[], ['i32x4.lt_s']],
        [[], ['i32x4.lt_u']],
        [[], ['i32x4.gt_s']],
        [[], ['i32x4.gt_u']],
        [[], ['i32x4.le_s']],
        [[], ['i32x4.le_u']],
        [[], ['i32x4.ge_s']],
        # 0x40
        [[], ['i32x4.ge_u']],
        [[], ['f32x4.eq']],
        [[], ['f32x4.ne']],
        [[], ['f32x4.lt']],
        [[], ['f32x4.gt']],
        [[], ['f32x4.le']],
        [[], ['f32x4.ge']],
        [[], ['f64x2.eq']],
        [[], ['f64x2.ne']],
        [[], ['f64x2.lt']],
        [[], ['f64x2.gt']],
        [[], ['f64x2.le']],
        [[], ['f64x2.ge']],
        [[], ['v128.not']],
        [[], ['v128.and']],
        [[], ['v128.andnot']],
        # 0x50
        [[], ['v128.or']],
        [[], ['v128.xor']],
        [[], ['v128.bitselect']],
        [[], ['v128.any_true']],
        [['mao', 'vl'], ['v128.load8_lane', 'mao', 'vl']],
        [['mao', 'vl'], ['v128.load16_lane', 'mao', 'vl']],
        [['mao', 'vl'], ['v128.load32_lane', 'mao', 'vl']],
        [['mao', 'vl'], ['v128.load64_lane', 'mao', 'vl']],
        [['mao', 'vl'], ['v128.store8_lane', 'mao', 'vl']],
        [['mao', 'vl'], ['v128.store16_lane', 'mao', 'vl']],
        [['mao', 'vl'], ['v128.store32_lane', 'mao', 'vl']],
        [['mao', 'vl'], ['v128.store64_lane', 'mao', 'vl']],
        [['mao'], ['v128.load32_zero', 'mao']],
        [['mao'], ['v128.load64_zero', 'mao']],
        [[], ['f32x4.demote_f64x2_zero']],
        [[], ['f64x2.promote_low_f32x4']],
        # 0x60
        [[], ['i8x16.abs']],
        [[], ['i8x16.neg']],
        [[], ['i8x16.popcnt']],
        [[], ['i8x16.all_true']],
        [[], ['i8x16.bitmask']],
        [[], ['i8x16.narrow_i16x8_s']],
        [[], ['i8x16.narrow_i16x8_u']],
        [[], ['f32x4.ceil']],
        [[], ['f32x4.floor']],
        [[], ['f32x4.trunc']],
        [[], ['f32x4.nearest']],
        [[], ['i8x16.shl']],
        [[], ['i8x16.shr_s']],
        [[], ['i8x16.shr_u']],
        [[], ['i8x16.add']],
        [[], ['i8x16.add_sat_s']],
        # 0x70
        [[], ['i8x16.add_sat_u']],
        [[], ['i8x16.sub']],
        [[], ['i8x16.sub_sat_s']],
        [[], ['i8x16.sub_sat_u']],
        [[], ['f64x2.ceil']],
        [[], ['f64x2.floor']],
        [[], ['i8x16.min_s']],
        [[], ['i8x16.min_u']],
        [[], ['i8x16.max_s']],
        [[], ['i8x16.max_u']],
        [[], ['f64x2.trunc']],
        [[], ['i8x16.avr_u']],
        [[], ['i16x8.extadd_pairwise_i8x16_s']],
        [[], ['i16x8.extadd_pairwise_i8x16_u']],
        [[], ['i32x4.extadd_pairwise_i16x8_s']],
        [[], ['i32x4.extadd_pairwise_i16x8_u']],
        # 0x80
        [[], ['i16x8.abs']],
        [[], ['i16x8.neg']],
        [[], ['i16x8.q15mulr_sat_s']],
        [[], ['i16x8.all_true']],
        [[], ['i16x8.bitmask']],
        [[], ['i16x8.narrow_i32x4_s']],
        [[], ['i16x8.narrow_i32x4_u']],
        [[], ['i16x8.extend_low_i8x16_s']],
        [[], ['i16x8.extend_high_i8x16_s']],
        [[], ['i16x8.extend_low_i8x16_u']],
        [[], ['i16x8.extend_high_i8x16_u']],
        [[], ['i16x8.shl']],
        [[], ['i16x8.shr_s']],
        [[], ['i16x8.shr_u']],
        [[], ['i16x8.add']],
        [[], ['i16x8.add_sat_s']],
        # 0x90
        [[], ['i16x8.add_sat_u']],
        [[], ['i16x8.sub']],
        [[], ['i16x8.sub_sat_s']],
        [[], ['i16x8.sub_sat_u']],
        [[], ['f64x2.nearest']],
        [[], ['i16x8.mul']],
        [[], ['i16x8.min_s']],
        [[], ['i16x8.min_u']],
        [[], ['i16x8.max_s']],
        [[], ['i16x8.max_u']],
        [],
        [[], ['i16x8.avr_u']],
        [[], ['i16x8.extmul_low_i8x16_s']],
        [[], ['i16x8.extmul_high_i8x16_s']],
        [[], ['i16x8.extmul_low_i8x16_u']],
        [[], ['i16x8.extmul_high_i8x16_u']],
        # 0xA0
        [[], ['i32x4.abs']],
        [[], ['i32x4.neg']],
        [],
        [[], ['i32x4.all_true']],
        [[], ['i32x4.bitmask']],
        [[], ['i32x4.narrow_i32x4_s']],
        [[], ['i32x4.narrow_i32x4_u']],
        [[], ['i32x4.extend_low_i16x8_s']],
        [[], ['i32x4.extend_high_i16x8_s']],
        [[], ['i32x4.extend_low_i16x8_u']],
        [[], ['i32x4.extend_high_i16x8_u']],
        [[], ['i32x4.shl']],
        [[], ['i32x4.shr_s']],
        [[], ['i32x4.shr_u']],
        [[], ['i32x4.add']],
        [],
        # 0xB0
        [],
        [[], ['i32x4.sub']],
        [],[],[],
        [[], ['i32x4.mul']],
        [[], ['i32x4.min_s']],
        [[], ['i32x4.min_u']],
        [[], ['i32x4.max_s']],
        [[], ['i32x4.max_u']],
        [[], ['i32x4.dot_i16x8_s']],
        [],
        [[], ['i32x4.extmul_low_i16x8_s']],
        [[], ['i32x4.extmul_high_i16x8_s']],
        [[], ['i32x4.extmul_low_i16x8_u']],
        [[], ['i32x4.extmul_high_i16x8_u']],
        # 0xC0
        [[], ['i64x2.abs']],
        [[], ['i64x2.neg']],
        [],
        [[], ['i64x2.all_true']],
        [[], ['i64x2.bitmask']],
        [],[],
        [[], ['i64x2.extend_low_i32x4_s']],
        [[], ['i64x2.extend_high_i32x4_s']],
        [[], ['i64x2.extend_low_i32x4_u']],
        [[], ['i64x2.extend_high_i32x4_u']],
        [[], ['i64x2.shl']],
        [[], ['i64x2.shr_s']],
        [[], ['i64x2.shr_u']],
        [[], ['i64x2.add']],
        [],
        # 0xD0
        [],
        [[], ['i64x2.sub']],
        [],[],[],
        [[], ['i64x2.mul']],
        [[], ['i64x2.eq']],
        [[], ['i64x2.ne']],
        [[], ['i64x2.lt_s']],
        [[], ['i64x2.gt_s']],
        [[], ['i64x2.le_s']],
        [[], ['i64x2.ge_s']],
        [[], ['i64x2.extmul_low_i8x16_s']],
        [[], ['i64x2.extmul_high_i8x16_s']],
        [[], ['i64x2.extmul_low_i8x16_u']],
        [[], ['i64x2.extmul_high_i8x16_u']],
        # 0xE0
        [[], ['f32x4.abs']],
        [[], ['f32x4.neg']],
        [],
        [[], ['f32x4.sqrt']],
        [[], ['f32x4.add']],
        [[], ['f32x4.sub']],
        [[], ['f32x4.mul']],
        [[], ['f32x4.div']],
        [[], ['f32x4.min']],
        [[], ['f32x4.max']],
        [[], ['f32x4.pmin']],
        [[], ['f32x4.pmax']],
        [[], ['f64x2.abs']],
        [[], ['f64x2.neg']],
        [],
        [[], ['f64x2.sqrt']],
        # 0xF0
        [[], ['f64x2.add']],
        [[], ['f64x2.sub']],
        [[], ['f64x2.mul']],
        [[], ['f64x2.div']],
        [[], ['f64x2.min']],
        [[], ['f64x2.max']],
        [[], ['f64x2.pmin']],
        [[], ['f64x2.pmax']],
        [[], ['i32x4.trunc_sat_f32x4_s']],
        [[], ['i32x4.trunc_sat_f32x4_u']],
        [[], ['f32x4.convert_i32x4_s']],
        [[], ['f32x4.convert_i32x4_u']],
        [[], ['i32x4.trunc_sat_f64x2_s_zero']],
        [[], ['i32x4.trunc_sat_f64x2_u_zero']],
        [[], ['f64x2.convert_low_i32x4_s']],
        [[], ['f64x2.convert_low_i32x4_u']],
    ],
    [],[],
]


def read_valtype(stream):
    code = stream.byte()
    return String(get_valtype(int(code)), code.data)


def read_reftype(stream):
    code = stream.byte()
    return String(get_reftype(int(code)), code.data)


def instruction(stream, indent_base=0, indent_level=0, indent_step=2):
    rpos = stream.rpos
    scode1 = stream.byte()
    code1 = int(scode1)
    ins = DISASM[code1]
    if code1 in (0xFC, 0xFD):
        scode2 = stream.leb128u()
        code2 = int(scode2)
        ins = ins[code2]
    data = stream.reload(rpos)
    if not ins:
        binary = ' '.join(f'0x{d:02x}' for d in data.data)
        raise NotImplementedError(f'unknown instruction: {binary}')

    asm = ins[1]
    if asm[0] in {'else', 'end'}:
        indent_level = max(0, indent_level - 1)
    indent_depth = (indent_base + indent_level) * indent_step
    indent = ' ' * indent_depth
    dprint(data, f'{indent}{asm[0]}')
    indent = indent + '  --> '

    for op in ins[0]:
        if isinstance(op, int):
            sfx = stream.byte()
            if op == int(sfx):
                dprint(sfx.data, f'{indent}(code:0x{op:02x})')
                continue
            raise NotImplementedError(
                'unknown instruction code:'
                f' {asm[0]} -> 0x{op:02x}'
            )

        if op in {
                'i32', 'i64',
                'did', 'eid', 'fid', 'gid', 'lid', 'mid',
                'tid', 'tid1', 'tid2',
                'xid',
        }:
            code = stream.leb128u()
            dprint(code.data, indent + str(int(code)))
            continue
        if op == 'f32':
            code = stream.load(4)
            dprint(code, indent + str(unpack('<f', code.data)[0]))
            continue
        if op == 'f64':
            code = stream.load(8)
            dprint(code, indent + str(unpack('<d', code.data)[0]))
            continue

        if op == ('vb16', 'vlt'):
            code = stream.load(16)
            dprint(code, indent + ' '.join(f'0x{b:02x}' for b in code.data))
            continue
        if op == 'vl':
            code = stream.byte()
            dprint(code.data, f'{indent}lane = 0x{int(code):02x}')
            continue

        if op == 'mao':
            code = stream.leb128u()
            dprint(code.data, f'{indent}align = {int(code)}')
            code = stream.leb128u()
            dprint(code.data, f'{indent}offset = {int(code)}')
            continue

        if op == 'bt':
            leb128 = stream.leb128()
            cbt = leb128[0]
            if cbt & 0x40:
                sbt = '(empty)' if cbt == 0x40 else get_valtype(cbt)
            else:
                sbt = str(decode_leb128s(leb128.data))
            dprint(leb128, indent + sbt)
            continue

        if op == 't+':
            leb128 = stream.leb128u()
            count = int(leb128)
            dprint(leb128.data, f'{indent}(types={count})')
            for _ in range(count):
                cvt = read_valtype(stream)
                dprint(cvt.data, f'{indent}{str(cvt)}')
            continue
        if op == 'lid+':
            leb128 = stream.leb128u()
            count = int(leb128)
            dprint(leb128.data, f'{indent}(types={count})')
            for _ in range(count):
                lid = stream.leb128u()
                dprint(lid.data, f'{indent}{str(lid)}')
            continue
        if op == 'ref':
            crt = read_reftype(stream)
            dprint(crt.data, f'{indent}{str(crt)}')
            continue

        raise NotImplementedError(f'{asm[0]} -> {op}')

    return asm[0]


def expression(stream, indent_base=0, indent_level=0, indent_step=2):
    while stream.remain() > 0:
        asm = instruction(stream, indent_base, indent_level, indent_step)
        if asm == 'end':
            break
        if asm in {'block', 'loop', 'if'}:
            expression(stream, indent_base, indent_level + 1, indent_step)


# -----------------------------------------------------------------------------

def section_remain(section):
    remain = section.load(section.remain())
    if len(remain):
        dprint(None, f'unknown data: size = {len(remain)}')
        dprint(remain, data_strings(remain.data))

def custom_section(section):
    name = section.utf8()
    dprint(name.data, f'name = "{name}"')
    byte = section.load(section.remain())
    dprint(byte, data_strings(byte.data))


def type_section(section):
    indent = ' ' * 2
    vsiz = section.leb128u()
    vlen = int(vsiz)
    dprint(vsiz.data, f'functype count = {vlen}')
    for typeidx in range(vlen):
        dprint(None, f'typeidx[{typeidx}]')
        code = section.byte()
        name = FUNCTYPE.get(int(code))
        if name is None:
            raise NotImplementedError(f'unknown code: 0x{int(code):02x}')
        dprint(code.data, f'{indent}{name}')
        result_type(section, 'param', indent)
        result_type(section, 'result', indent)
    section_remain(section)


def import_section(section):
    indent = ' ' * 2
    nindent = ' ' * 4
    vsiz = section.leb128u()
    vlen = int(vsiz)
    dprint(vsiz.data, f'import count = {vlen}')
    for idx in range(vlen):
        dprint(None, f'import[{idx}]')
        mod = section.utf8()
        dprint(mod.data, f'{indent}module = "{str(mod)}"')
        name = section.utf8()
        dprint(name.data, f'{indent}name = "{str(name)}"')
        imp = section.byte()
        mode = int(imp)
        mnam = IMPORT_MODE.get(mode)
        dprint(imp.data, f'{indent}{mnam}')
        if mode == 0:
            typeidx = section.leb128u()
            dprint(typeidx.data, f'{nindent}typeidx = {int(typeidx)}')
        elif mode == 1:
            reference_type(section, nindent)
            limits(section, nindent)
        elif mode == 2:
            limits(section, nindent)
        elif mode == 3:
            value_type(section, nindent)
            mutability(section, nindent)
        else:
            raise NotImplementedError(f'unknown import section: {mode}')
    section_remain(section)


def function_section(section):
    indent = ' ' * 2
    vsiz = section.leb128u()
    vlen = int(vsiz)
    dprint(vsiz.data, f'typeidx count = {vlen}')
    for idx in range(vlen):
        code = section.leb128u()
        dprint(code.data, f'{indent}typeidx[{idx}] = {int(code)}')
    section_remain(section)


def table_section(section):
    indent = ' ' * 2
    vsiz = section.leb128u()
    vlen = int(vsiz)
    dprint(vsiz.data, f'table count = {vlen}')
    for idx in range(vlen):
        dprint(None, f'table[{idx}]')
        reference_type(section, indent)
        limits(section, indent)
    section_remain(section)


def memory_section(section):
    indent = ' ' * 2
    vsiz = section.leb128u()
    vlen = int(vsiz)
    dprint(vsiz.data, f'memtype count = {vlen}')
    for idx in range(vlen):
        dprint(None, f'mem[{idx}]')
        limits(section, indent)
    section_remain(section)


def global_section(section):
    indent = ' ' * 2
    vsiz = section.leb128u()
    vlen = int(vsiz)
    dprint(vsiz.data, f'global count = {vlen}')
    for idx in range(vlen):
        dprint(None, f'global[{idx}]')
        value_type(section, indent + 'valtype = ')
        mutability(section, indent + 'mut = ')
        dprint(None, f'{indent}expr')
        expression(section, 2)
    section_remain(section)


def export_section(section):
    indent = ' ' * 2
    nindent = ' ' * 4
    vsiz = section.leb128u()
    vlen = int(vsiz)
    dprint(vsiz.data, f'export count = {vlen}')
    for idx in range(vlen):
        dprint(None, f'export[{idx}]')
        name = section.utf8()
        dprint(name.data, f'{indent}name = "{str(name)}"')
        exp = section.byte()
        mode = int(exp)
        mnam = EXPORT_MODE.get(mode)
        dprint(exp.data, f'{indent}{mnam}')
        if mnam is None:
            raise NotImplementedError(f'unknown export section: {mode}')
        etid = section.leb128u()
        dprint(etid.data, f'{nindent}{mnam}idx = {int(etid)}')
    section_remain(section)


def start_section(section):
    funcidx = section.leb128u()
    dprint(funcidx.data, f'funcidx = {int(funcidx)}')
    section_remain(section)


def element_section(section):
    indent = ' ' * 2
    vsiz = section.leb128u()
    vlen = int(vsiz)
    dprint(vsiz.data, f'element count = {vlen}')
    for idx in range(vlen):
        code = section.byte()
        mode = int(code)
        dprint(code.data, f'elem[{idx}] (mode:{mode})')
        if mode >= 8:
            raise NotImplementedError(f'unknown element: {mode}')
        if mode in (2, 6):
            tabidx = section.leb128u()
            dprint(tabidx.data, f'{indent}tableidx = {int(tabidx)}')
        if not mode & 1:
            dprint(None, f'{indent}expr')
            expression(section, 2)
        if mode & 4:
            if mode & 3:
                cvt = read_valtype(section)
                dprint(cvt.data, f'{indent}{str(cvt)}')
            exprs = section.leb128u()
            count = int(exprs)
            dprint(exprs.data, f'{indent}expr count = {count}')
            for idx in range(count):
                dprint(None, f'{indent}expr[{idx}]')
                expression(section, 2)
        else:
            if mode & 3:
                kind = section.byte()
                if kind != 0:
                    raise NotImplementedError(f'unknown elemkind: {int(kind)}')
                dprint(kind.data, f'{indent}funcref')
            exprs = section.leb128u()
            count = int(exprs)
            dprint(exprs.data, f'{indent}funcidx count = {count}')
            for idx in range(count):
                fid = section.leb128u()
                dprint(fid.data, f'{indent}funcidx[{idx}] = {int(fid)}')
    section_remain(section)


def code_section(section):
    indent = ' ' * 2
    vsiz = section.leb128u()
    vlen = int(vsiz)
    dprint(vsiz.data, f'code count = {vlen}')
    for idx in range(vlen):
        csz = section.leb128u()
        dprint(None, f'code[{idx}]')
        dprint(csz.data, f'{indent}code size = {int(csz)}')
        code = section.load(int(csz))
        lsz = code.leb128u()
        dprint(lsz.data, f'{indent}local size = {int(lsz)}')
        for lnum in range(int(lsz)):
            tcnt = code.leb128u()
            dprint(None, f'{indent}local[{lnum}]')
            dprint(tcnt.data, f'{indent}  type count = {int(tcnt)}')
            cvt = read_valtype(code)
            dprint(cvt.data, f'{indent}  type = {str(cvt)}')
        expression(code, 1)
        section_remain(code)
    section_remain(section)


def data_section(section):
    indent = ' ' * 2
    vsiz = section.leb128u()
    vlen = int(vsiz)
    dprint(vsiz.data, f'data count = {vlen}')
    for idx in range(vlen):
        code = section.leb128u()
        mode = int(code)
        dprint(code.data, f'data[{idx}] (mode={mode})')
        if mode >= 3:
            raise NotImplementedError(f'unknown data: mode={mode}')
        if mode == 2:
            memidx = section.leb128u()
            dprint(memidx.code, f'{indent}memidx = {int(memidx)}')
        if mode in (0, 2):
            expression(section, 1)
        bsz = section.leb128u()
        dprint(bsz.data, f'{indent}init size = {int(bsz)}')
        bdt = section.load(int(bsz))
        dprint(bdt, data_strings(bdt.data, indent + '  '))
    section_remain(section)


def datacount_section(section):
    count = section.long()
    dprint(count.data, f'data count = {int(count)}')
    section_remain(section)


# -----------------------------------------------------------------------------


FILE_MAGIC = b'\x00asm'

SECTION_NAME = (
    'Custom',      # 0
    'Type',        # 1
    'Import',      # 2
    'Function',    # 3
    'Table',       # 4
    'Memory',      # 5
    'Global',      # 6
    'Export',      # 7
    'Start',       # 8
    'Element',     # 9
    'Code',        # 10
    'Data',        # 11
    'Data Count',  # 12
)

SECTION_FUNC = (
    custom_section,     # 0
    type_section,       # 1
    import_section,     # 2
    function_section,   # 3
    table_section,      # 4
    memory_section,     # 5
    global_section,     # 6
    export_section,     # 7
    start_section,      # 8
    element_section,    # 9
    code_section,       # 10
    data_section,       # 11
    datacount_section,  # 12
)


def main():
    global ADRFMT, BYTESW, LEFTW, LPAD

    parser = argparse.ArgumentParser()
    parser.add_argument('-w', '--width', type=int, default=8)
    parser.add_argument('file')

    args = parser.parse_args()
    path = args.file
    with open(path, 'rb') as fp:
        data = fp.read()
    file = ReadData(path, data, 0)

    fposw = len(f'{len(file) - 1:x}')
    ADRFMT = f'%0{fposw}x:'
    BYTESW = args.width
    LEFTW = fposw + 2 + BYTESW * 3 - 1
    LPAD = ' ' * LEFTW

    print(LINE_SEP)
    print(f'Path: {path}')
    print(LINE_SEP)

    magic = file.read(4)
    dprint(magic, f'magic = {repr(magic.data)}')
    if magic.data != FILE_MAGIC:
        raise ValueError()

    version = file.long()
    dprint(version.data, f'version = {int(version)}')

    while file.remain():
        print(LINE_SEP)

        secid = file.byte()
        sid = int(secid)
        dprint(secid.data, f'{SECTION_NAME[sid]} Section (id={sid})')

        secsize = file.leb128u()
        ssz = int(secsize)
        dprint(secsize.data, f'section size = {ssz}')

        SECTION_FUNC[sid](file.read(ssz))


sys.exit(main())

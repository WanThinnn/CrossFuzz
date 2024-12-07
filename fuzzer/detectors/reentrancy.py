#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from z3 import simplify
from utils.utils import convert_stack_value_to_int

class ReentrancyDetector():
    '''
    
    Bộ phát hiện tái nhập (Reentrancy Detector) cho các hợp đồng thông minh.
    Thuộc tính:
        swc_id (int): Mã nhận dạng SWC cho lỗ hổng tái nhập.
        severity (str): Mức độ nghiêm trọng của lỗ hổng.
        sloads (dict): Lưu trữ các chỉ số bộ nhớ đã tải.
        calls (set): Tập hợp các cuộc gọi đã thực hiện.
    Phương thức:
        __init__(): Khởi tạo đối tượng ReentrancyDetector.
        init(): Khởi tạo các thuộc tính của đối tượng.
        detect_reentrancy(tainted_record, current_instruction, transaction_index): Phát hiện lỗ hổng tái nhập dựa trên các chỉ dẫn hiện tại và các giao dịch trước đó.

    '''
    def __init__(self):
        self.init()

    def init(self):
        self.swc_id = 107
        self.severity = "High"
        self.sloads = {}
        self.calls = set()

    def detect_reentrancy(self, tainted_record, current_instruction, transaction_index):
        '''
        Phát hiện lỗi reentrancy trong hợp đồng thông minh.
        Hàm này kiểm tra các lệnh trong hợp đồng thông minh để phát hiện lỗi reentrancy, 
        một loại lỗi bảo mật phổ biến trong các hợp đồng thông minh Ethereum.
        Args:
            tainted_record (object): Bản ghi chứa thông tin về các giá trị bị ảnh hưởng.
            current_instruction (dict): Lệnh hiện tại đang được thực thi.
            transaction_index (int): Chỉ số của giao dịch hiện tại.
        Returns:
            tuple: Trả về một tuple chứa địa chỉ chương trình (program counter) và chỉ số giao dịch 
                   nếu phát hiện lỗi reentrancy, ngược lại trả về (None, None).
        '''


        # Kiểm tra xem lệnh hiện tại có phải là lệnh SLOAD không.
        if current_instruction["op"] == "SLOAD":
            if tainted_record and tainted_record.stack and tainted_record.stack[-1]:
                storage_index = convert_stack_value_to_int(current_instruction["stack"][-1])
                self.sloads[storage_index] = current_instruction["pc"], transaction_index
        # Kiểm tra xem lệnh hiện tại có phải là lệnh CALL không và có lưu trữ SLOAD.
        elif current_instruction["op"] == "CALL" and self.sloads:
            gas = convert_stack_value_to_int(current_instruction["stack"][-1])
            value = convert_stack_value_to_int(current_instruction["stack"][-3])
            if gas > 2300 and (value > 0 or tainted_record and tainted_record.stack and tainted_record.stack[-3]):
                self.calls.add((current_instruction["pc"], transaction_index))
            if gas > 2300 and tainted_record and tainted_record.stack and tainted_record.stack[-2]:
                self.calls.add((current_instruction["pc"], transaction_index))
                for pc, index in self.sloads.values():
                    if pc < current_instruction["pc"]:
                        return current_instruction["pc"], index
        # Kiểm tra xem lệnh hiện tại có phải là lệnh SSTORE không và có lưu trữ SLOAD.
        elif current_instruction["op"] == "SSTORE" and self.calls:
            if tainted_record and tainted_record.stack and tainted_record.stack[-1]:
                storage_index = convert_stack_value_to_int(current_instruction["stack"][-1])
                if storage_index in self.sloads:
                    for pc, index in self.calls:
                        if pc < current_instruction["pc"]:
                            return pc, index
        # Clear sloads and calls from previous transactions
        elif current_instruction["op"] in ["STOP", "RETURN", "REVERT", "ASSERTFAIL", "INVALID", "SUICIDE", "SELFDESTRUCT"]:
            self.sloads = {}
            self.calls = set()
        return None, None 

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from z3 import is_expr
from utils import settings

class UnsafeDelegatecallDetector():
    
    '''
    Phát hiện việc sử dụng delegatecall không an toàn.
    Attributes:
        swc_id (int): Mã SWC của lỗ hổng.
        severity (str): Mức độ nghiêm trọng của lỗ hổng.
        delegatecall (tuple or None): Thông tin về delegatecall không an toàn được phát hiện.
    Methods:
        __init__(): Khởi tạo đối tượng và gọi phương thức init.
        init(): Khởi tạo các thuộc tính của đối tượng.
        detect_unsafe_delegatecall(current_instruction, tainted_record, individual, previous_instruction, transaction_index):
            Phát hiện delegatecall không an toàn trong các lệnh hiện tại.
    '''
    def __init__(self):
        self.init()

    def init(self):
        self.swc_id = 112
        self.severity = "High"
        self.delegatecall = None

    def detect_unsafe_delegatecall(self, current_instruction, tainted_record, individual, previous_instruction, transaction_index):
        """
        Hàm này kiểm tra các lệnh hiện tại và các bản ghi bị nhiễm để phát hiện các cuộc gọi delegate không an toàn.
        Nếu phát hiện cuộc gọi delegate không an toàn, nó sẽ trả về vị trí chương trình (program counter) và chỉ số giao dịch.
        
        Args:
            - current_instruction (dict): Lệnh hiện tại đang được thực thi.
            - tainted_record (object): Bản ghi bị nhiễm chứa thông tin về ngăn xếp và các biến bị nhiễm.
            - individual (object): Cá nhân chứa giải pháp hiện tại.
            - previous_instruction (dict): Lệnh trước đó đã được thực thi.
            - transaction_index (int): Chỉ số của giao dịch hiện tại.
        
        Returns:
            tuple: Vị trí chương trình (program counter) và chỉ số giao dịch nếu phát hiện cuộc gọi delegate không an toàn, 
                   ngược lại trả về (None, None).
        """
        
        if current_instruction["op"] == "DELEGATECALL":
            if tainted_record and tainted_record.stack[-2] and is_expr(tainted_record.stack[-2][0]):
                for index in range(len(individual.solution)):
                    if individual.solution[index]["transaction"]["from"] not in settings.ATTACKER_ACCOUNTS:
                        return None, None
                self.delegatecall = current_instruction["pc"], transaction_index
        elif current_instruction["op"] == "STOP" and self.delegatecall:
            return self.delegatecall
        return None, None

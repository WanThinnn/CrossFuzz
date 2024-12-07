#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from z3 import is_expr
from utils import settings

class UnprotectedSelfdestructDetector():
    '''
    UnprotectedSelfdestructDetector là một lớp được thiết kế để phát hiện việc sử dụng các thao tác selfdestruct không được bảo vệ trong các hợp đồng thông minh.
    Thuộc tính:
        swc_id (int): ID SWC (Phân loại điểm yếu hợp đồng thông minh) cho selfdestruct không được bảo vệ.
        severity (str): Mức độ nghiêm trọng của vấn đề được phát hiện.
        trusted_arguments (str): Một chuỗi chứa các đối số đáng tin cậy.
    Phương thức:
        __init__():
            Khởi tạo một thể hiện của UnprotectedSelfdestructDetector và gọi phương thức init.
        init():
            Thiết lập các giá trị ban đầu cho swc_id, severity và trusted_arguments.
        detect_unprotected_selfdestruct(current_instruction, tainted_record, individual, transaction_index):
            Phát hiện các thao tác selfdestruct không được bảo vệ trong giao dịch đã cho.
            Tham số:
                current_instruction (dict): Lệnh hiện tại đang được phân tích.
                tainted_record (list): Một bản ghi của dữ liệu bị nhiễm.
                individual (object): Giải pháp cá nhân đang được phân tích.
                transaction_index (int): Chỉ số của giao dịch hiện tại.
            Trả về:
                tuple: Một bộ chứa bộ đếm chương trình (pc) và chỉ số giao dịch nếu phát hiện selfdestruct không được bảo vệ, nếu không trả về (None, None).
    '''
    def __init__(self):
        self.init()

    def init(self):
        self.swc_id = 106
        self.severity = "High"
        self.trusted_arguments = ""

    def detect_unprotected_selfdestruct(self, current_instruction, tainted_record, individual, transaction_index):
        '''
        Phát hiện các thao tác selfdestruct không được bảo vệ trong giao dịch đã cho.
            
        Tham số:
            - current_instruction (dict): Lệnh hiện tại đang được phân tích.
            - tainted_record (list): Một bản ghi của dữ liệu bị nhiễm.
            - individual (object): Giải pháp cá nhân đang được phân tích.
            - transaction_index (int): Chỉ số của giao dịch hiện tại.
            
        Trả về: 
            tuple: Một bộ chứa bộ đếm chương trình (pc) và chỉ số giao dịch nếu phát hiện selfdestruct không được bảo vệ,
            nếu không trả về (None, None).
        '''
        if current_instruction["op"] in ["SELFDESTRUCT", "SUICIDE"]:
            for i in range(transaction_index):
                # Check if it is a trusted account
                if individual.solution[i]["transaction"]["from"] not in settings.ATTACKER_ACCOUNTS:
                    # Add the arguments to the list of trusted arguments
                    if individual.solution[i]["transaction"]["data"] not in self.trusted_arguments:
                        self.trusted_arguments += individual.solution[i]["transaction"]["data"]
            # An unprotected selfdestruct is detected if the sender of the transaction is an attacker and not trusted by a trusted account
            if individual.solution[transaction_index]["transaction"]["from"] in settings.ATTACKER_ACCOUNTS and not individual.solution[transaction_index]["transaction"]["from"].replace("0x", "") in self.trusted_arguments:
                return current_instruction["pc"], transaction_index
        return None, None

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from z3 import is_expr
from utils import settings
from utils.utils import convert_stack_value_to_int, convert_stack_value_to_hex

class LeakingEtherDetector():

    '''
    Phát hiện rò rỉ Ether.
    Thuộc tính:
        swc_id (int): ID của SWC (Smart Contract Weakness Classification).
        severity (str): Mức độ nghiêm trọng của lỗ hổng.
        leaks (dict): Từ điển chứa thông tin về các giao dịch bị rò rỉ.
        spenders (set): Tập hợp các tài khoản đã chi tiêu Ether.
    Phương thức:
        __init__(): Khởi tạo đối tượng LeakingEtherDetector.
        init(): Khởi tạo các thuộc tính của đối tượng.
        detect_leaking_ether(current_instruction, taint_record, individual, transaction_index, previous_branch):
            Phát hiện rò rỉ Ether dựa trên các thông tin về giao dịch và các lệnh hiện tại.
            Trả về tuple chứa thông tin về lệnh và chỉ số giao dịch nếu phát hiện rò rỉ, ngược lại trả về (None, None).
    '''
    def __init__(self):
        self.init()

    def init(self):
        self.swc_id = 105 # Đặt ID tiêu chuẩn SWC (Smart Contract Weakness Classification) cho loại lỗ hổng này.
        self.severity = "High" # Đặt mức độ nghiêm trọng của lỗ hổng.
        self.leaks = {}
        self.spenders = set()

    def detect_leaking_ether(self, current_instruction, taint_record, individual, transaction_index, previous_branch):

        '''
        Phát hiện rò rỉ ether trong hợp đồng thông minh.
        Hàm này kiểm tra các lệnh hiện tại trong quá trình thực thi hợp đồng thông minh để phát hiện
        các trường hợp rò rỉ ether, tức là khi ether được chuyển đến các tài khoản không đáng tin cậy.
        
        Tham số:
        - current_instruction (dict): Lệnh hiện tại đang được thực thi.
        - taint_record (TaintRecord): Bản ghi taint của các giá trị trong ngăn xếp.
        - individual (Individual): Cá nhân hiện tại đang được kiểm tra.
        - transaction_index (int): Chỉ số của giao dịch hiện tại.
        - previous_branch (Branch): Nhánh trước đó trong quá trình thực thi.
        
        Trả về:
        - tuple: (pc, transaction_index) nếu phát hiện rò rỉ ether, ngược lại trả về (None, None).
        '''
        # Kiểm tra xem lệnh hiện tại có phải là lệnh STOP không.
        if current_instruction["op"] == "STOP":
            if individual.solution[transaction_index]["transaction"]["value"] > 0:
                self.spenders.add(individual.solution[transaction_index]["transaction"]["from"])
            
            if transaction_index in self.leaks:
                # Kiểm tra xem người gửi không phải là người chi tiêu.
                if individual.solution[transaction_index]["transaction"]["from"] not in self.spenders:
                    return self.leaks[transaction_index]
        # Kiểm tra xem lệnh hiện tại có phải là lệnh CALL không.
        elif current_instruction["op"] == "CALL":
            to = "0x"+convert_stack_value_to_hex(current_instruction["stack"][-2]).lstrip("0")
            # Kiểm tra xem địa chỉ đích có trong tài khoản tấn công không và có phải là người gửi không.
            if to in settings.ATTACKER_ACCOUNTS and to == individual.solution[transaction_index]["transaction"]["from"]:
                # Kiểm tra xem giá trị stack[-3] có lớn hơn 0 không hoặc bản ghi taint và stack[-3] và là biểu thức và "balance" trong biểu thức đó.
                if convert_stack_value_to_int(current_instruction["stack"][-3]) > 0 or taint_record and taint_record.stack[-3] and is_expr(taint_record.stack[-3][0]) and "balance" in str(taint_record.stack[-3][0]):
                    # Check if the destination did not spend ether
                    if not to in self.spenders:
                        # Check if the destination address is not passed as an argument
                        address_passed_as_argument = False
                        for i in range(transaction_index):
                            for argument in individual.chromosome[i]["arguments"]:
                                if argument in settings.ATTACKER_ACCOUNTS and individual.solution[i]["transaction"]["from"] not in settings.ATTACKER_ACCOUNTS:
                                    address_passed_as_argument = True
                        if not address_passed_as_argument:
                            self.leaks[transaction_index] = current_instruction["pc"], transaction_index
        return None, None # Trả về giá trị None nếu không có rò rỉ ether.

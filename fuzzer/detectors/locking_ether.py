#!/usr/bin/env python3
# -*- coding: utf-8 -*-

class LockingEtherDetector():

    '''
    Phát hiện khóa Ether không mong muốn.
    Attributes:
        swc_id (int): Mã SWC của lỗi phát hiện.
        severity (str): Mức độ nghiêm trọng của lỗi phát hiện.
    Methods:
        __init__(): Khởi tạo đối tượng LockingEtherDetector.
        init(): Khởi tạo các thuộc tính của đối tượng.
        detect_locking_ether(cfg, current_instruction, individual, transaction_index):
            Phát hiện khóa Ether không mong muốn trong giao dịch.
            Args:
                cfg: Cấu hình của hợp đồng thông minh.
                current_instruction: Lệnh hiện tại đang được thực thi.
                individual: Cá nhân thực hiện giao dịch.
                transaction_index: Chỉ số của giao dịch trong chuỗi giao dịch.
            Returns:
                Tuple chứa địa chỉ lệnh (program counter) và chỉ số giao dịch nếu phát hiện khóa Ether, ngược lại trả về (None, None).
    '''
    def __init__(self):
        self.init()

    def init(self):
        self.swc_id = 132 # Đặt ID tiêu chuẩn SWC (Smart Contract Weakness Classification) cho loại lỗ hổng này.
        self.severity = "Medium" # Đặt mức độ nghiêm trọng của lỗ hổng.

    def detect_locking_ether(self, cfg, current_instruction, individual, transaction_index):
        
        '''
        Phát hiện tình trạng khóa ether trong hợp đồng thông minh.
        Hàm này kiểm tra xem liệu một giao dịch có bị khóa ether hay không, tức là không thể gửi ether đi nhưng có thể nhận ether.
        Tham số:
        - cfg: Cấu hình của hợp đồng thông minh.
        - current_instruction: Lệnh hiện tại đang được thực thi.
        - individual: Cá nhân đang thực hiện giao dịch.
        - transaction_index: Chỉ số của giao dịch hiện tại.
        Trả về:
        - Một tuple chứa địa chỉ của lệnh hiện tại (program counter) và chỉ số của giao dịch nếu phát hiện tình trạng khóa ether.
        - (None, None) nếu không phát hiện tình trạng khóa ether.
        '''
        # Check if we cannot send ether
        if not cfg.can_send_ether:
            # Check if we can receive ether
            if current_instruction["op"] == "STOP" and individual.solution[transaction_index]["transaction"]["value"] > 0:
                return current_instruction["pc"], transaction_index
        return None, None # Trả về giá trị None nếu không phát hiện tình trạng khóa ether.

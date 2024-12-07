#!/usr/bin/env python3
# -*- coding: utf-8 -*-

''' Toán tử lai ghép trong thuật toán di truyền '''

import random

from utils import settings
from ...plugin_interfaces.operators.crossover import Crossover
from ...components.individual import Individual
'''
    Kế thừa từ lớp Crossover trong module plugin_interfaces.
    Indivial từ components.indiviual đại diện cho cá thể trong thuật toán di truyền
'''
class Crossover(Crossover):
    def __init__(self, pc):
        '''
        Nhận tham số pc là xác suất lai ghép (thường nằm trong khoảng 0.25 ~ 1.0)

        Kiểm tra giá trị pc có hợp lệ không (nằm trong khoảng (0.0, 1.0]). Nếu không hợp lệ, ném ra ngoại lệ ValueError

        '''
        if pc <= 0.0 or pc > 1.0:
            raise ValueError('Invalid crossover probability')

        self.pc = pc

    def cross(self, father, mother):
        '''
        Nhận hai tham số father và mother là các cá thể cần lai ghép
        '''

        do_cross = True if random.random() <= self.pc else False # Xác định xem có lai ghép không

        if mother is None:  # Nếu cá thể mẹ None thì trả về bản sao cá thể cha
            return father.clone(), father.clone()

        _father = father.clone() # bản sao cá thể cha
        _mother = mother.clone() # bản sao cá thể mẹ

        if not do_cross or len(father.chromosome) + len(mother.chromosome) > settings.MAX_INDIVIDUAL_LENGTH:
            return _father, _mother # Nếu không thực hiện lai ghép hoặc tổng chiều dài nhiễm sắc thể của father và mother vượt quá MAX_INDIVIDUAL_LENGTH, trả về hai bản sao

        """
            Tạo hai cá thể con child1 và child2 với nhiễm sắc thể kết hợp từ father và mother.
            Trả về child1 và child2
        """
        child1 = Individual(generator=_father.generator)
        child1.init(chromosome=_father.chromosome + _mother.chromosome)

        child2 = Individual(generator=_mother.generator)
        child2.init(chromosome=_mother.chromosome + _father.chromosome)

        return child1, child2

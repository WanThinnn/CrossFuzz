#!/usr/bin/env python3
# -*- coding: utf-8 -*-

''' Crossover operator implementation. '''

import random

from fuzzer.utils import settings
from ...plugin_interfaces.operators.crossover import Crossover
from ...components.individual import Individual


class DataDependencyCrossover(Crossover):
    def __init__(self, pc, env):
        '''
        Nhận:
            pc: là xác suất lai ghép (thường nằm trong khoảng 0.25 ~ 1.0)
            env: Môi trường chứa thông tin về phụ thuộc dữ liệu (data_dependencies)
        Kiểm tra giá trị pc có hợp lệ không (nằm trong khoảng (0.0, 1.0]). Nếu không hợp lệ, ném ra ngoại lệ ValueError
        '''
        if pc <= 0.0 or pc > 1.0:
            raise ValueError('Invalid crossover probability')

        self.pc = pc
        self.env = env

    def cross(self, father, mother):
        '''
        Nhận hai tham số father và mother là các cá thể cần lai ghép
        '''

        do_cross = True if random.random() <= self.pc else False # Xác định xem có lai ghép không

        if mother is None: # Nếu cá thể mẹ None thì trả về bản sao cá thể cha
            return father.clone(), father.clone()

        _father = father.clone() # bản sao cá thể cha
        _mother = mother.clone() # bản sao cá thể mẹ

        if not do_cross or len(father.chromosome) + len(mother.chromosome) > settings.MAX_INDIVIDUAL_LENGTH:
            return _father, _mother # Nếu không thực hiện lai ghép hoặc tổng chiều dài nhiễm sắc thể của father và mother vượt quá MAX_INDIVIDUAL_LENGTH, trả về hai bản sao

        """
        extract_reads_and_writes lấy tập hợp các biến được đọc (read) và ghi (write) của từng cá thể
        """
        father_reads, father_writes = DataDependencyCrossover.extract_reads_and_writes(_father, self.env)
        mother_reads, mother_writes = DataDependencyCrossover.extract_reads_and_writes(_mother, self.env)


        """
        Thực hiện kiểm tra xung đột giữa father và mother
            + Nếu mother_reads có giao với father_writes thì tạo child1 từ father và mother, nếu không thì lấy child1 là bản sao cuả father
            + Nếu father_reads có giao với mother_writes thì tạo child2 từ father và mother, nếu không thì lấy child2 là bản sao cuả mother
        """
        if not mother_reads.isdisjoint(father_writes):
            child1 = Individual(generator=_father.generator, other_generators=_father.other_generators)
            child1.init(chromosome=_father.chromosome + _mother.chromosome)
        else:
            child1 = _father

        if not father_reads.isdisjoint(mother_writes):
            child2 = Individual(generator=_mother.generator, other_generators=_mother.other_generators)
            child2.init(chromosome=_mother.chromosome + _father.chromosome)
        else:
            child2 = _mother

        return child1, child2

    @staticmethod
    def extract_reads_and_writes(individual, env):
        """
        Trích xuất các biến được đọc (read) và ghi (write) từ nhiễm sắc thể của một cá thể dựa trên phụ thuộc dữ liệu trong môi trường (env)
        Duyệt qua từng gene trong nhiễm sắc thể, xác định các biến liên quan bằng cách sử dụng data_dependencies
        """
        reads, writes = set(), set()

        for t in individual.chromosome:
            _function_hash = t["arguments"][0]
            if _function_hash in env.data_dependencies:
                reads.update(env.data_dependencies[_function_hash]["read"])
                writes.update(env.data_dependencies[_function_hash]["write"])

        return reads, writes

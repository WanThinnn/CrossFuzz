#!/usr/bin/env python
# -*- coding: utf-8 -*-

''' Module for Genetic Algorithm crossover operator class '''

from ..metaclasses import CrossoverMeta
"""
Triển khai một lớp cơ sở (Crossover) để cung cấp giao diện (interface) cho các 
thao tác lai ghép (crossover) trong thuật toán di truyền (Genetic Algorithm - GA)
"""

class Crossover(metaclass=CrossoverMeta):
    '''
    Lớp này không chứa logic cụ thể, mà được thiết kế như một lớp trừu tượng (abstract class), 
    giúp các lớp con có thể kế thừa và tùy chỉnh hành vi lai ghép theo nhu cầu riêng
    '''

    # Đại diện cho xác suất lai ghép (probability of crossover)
    pc = 0.8 #là xác suất để một cặp cha mẹ được chọn thực hiện lai ghép trong thuật toán di truyền

    def cross(self, father, mother):
        '''
        Called when we need to cross parents to generate children.

        :param father: The parent individual to be crossed.
        :type father: GAIndividual

        :param mother: The parent individual to be crossed.
        :type mother: GAIndividual

        :return children: Two new children individuals.
        :type children: Tuple of two GAIndividual objects.
        '''
        raise NotImplementedError #Dùng để thông báo rằng phương thức này phải được triển khai bởi các lớp con. Nếu không, việc gọi phương thức sẽ gây lỗi


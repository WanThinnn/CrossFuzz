#!/usr/bin/env python
# -*- coding: utf-8 -*-

''' Module for Genetic Algorithm selection operator class '''

from ..metaclasses import SelectionMeta
'''
Triển khai một lớp cơ sở (Selection) để cung cấp giao diện (interface) cho thao tác chọn lọc (selection) 
trong thuật toán di truyền (Genetic Algorithm - GA)


'''
class Selection(metaclass=SelectionMeta):
    '''
    Lớp này đóng vai trò như một lớp trừu tượng (abstract class)
    cho phép các lớp con kế thừa và triển khai các phương pháp chọn lọc khác nhau
    '''

    def select(self, population): #population: Quần thể hiện tại, chứa tất cả các cá thể (individuals) trong GA
        '''
        Called when we need to select parents from a population to later breeding.

        :param population: The current population.
        :type population: Population

        :return parents: Two selected individuals for crossover.
        :type parents: Tuple of tow GAIndividual objects.
        '''
        raise NotImplementedError #Dùng để thông báo rằng phương thức này phải được triển khai bởi các lớp con. Nếu không, việc gọi phương thức sẽ gây lỗi

'''
Python Code to find and plot time of Insertion and Merge Sort
Developed by: Hamza Haroon 
Design and Analysis of Algorithms
'''
import random
import time
import sys
import matplotlib.pyplot as plt


def insertion_sort(arr):
    for i in range(1, len(arr)):
        key = arr[i]
        j = i - 1
        while j >= 0 and key < arr[j]:
            arr[j + 1] = arr[j]
            j -= 1
        arr[j + 1] = key

def merge_sort(arr):
    if len(arr) > 1:
        mid = len(arr) // 2
        left_half = arr[:mid]
        right_half = arr[mid:]

        merge_sort(left_half)
        merge_sort(right_half)

        i = j = k = 0

        while i < len(left_half) and j < len(right_half):
            if left_half[i] < right_half[j]:
                arr[k] = left_half[i]
                i += 1
            else:
                arr[k] = right_half[j]
                j += 1
            k += 1

        while i < len(left_half):
            arr[k] = left_half[i]
            i += 1
            k += 1

        while j < len(right_half):
            arr[k] = right_half[j]
            j += 1
            k += 1

input_sizes = [1, 10, 100, 1000, 5000, 10000, 15000, 20000, 30000, 40000, 50000, 60000, 70000]   

insertion_sort_times = []
merge_sort_times = []

for size in input_sizes:
    random_array = random.sample(range(1, 10**10), size)

    start_time = time.time()
    insertion_sort(random_array.copy())
    insertion_sort_times.append(time.time() - start_time)

    start_time = time.time()
    merge_sort(random_array.copy())
    merge_sort_times.append(time.time() - start_time)

plt.figure(figsize=(8, 6))
plt.plot(input_sizes, insertion_sort_times, marker='o', label='Insertion Sort')
plt.plot(input_sizes, merge_sort_times, marker='o', label='Merge Sort')
plt.xlabel('Input Size')
plt.ylabel('Execution Time (seconds)')
plt.title('Comparison of Insertion Sort and Merge Sort')
plt.legend()
plt.grid(True)
plt.yscale('log')  
plt.show()
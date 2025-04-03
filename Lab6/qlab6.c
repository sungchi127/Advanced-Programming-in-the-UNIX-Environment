// void quick_sort(long *numbers, int left, int right) {
//     if (left >= right) {
//         return;
//     }

//     int i = left;
//     int j = right;
//     long pivot = numbers[left];

//     while (i < j) {
//         while (i < j && numbers[j] >= pivot) {
//             j--;
//         }
//         if (i < j) {
//             numbers[i] = numbers[j];
//             i++;
//         }

//         while (i < j && numbers[i] < pivot) {
//             i++;
//         }
//         if (i < j) {
//             numbers[j] = numbers[i];
//             j--;
//         }
//     }

//     numbers[i] = pivot;
//     quick_sort(numbers, left, i - 1);
//     quick_sort(numbers, i + 1, right);
// }

// void sort(long *numbers, int n) {
//     quick_sort(numbers, 0, n - 1);
// }
////////////////////////////////////////

void quick_sort(long *numbers, int left, int right) {
    if (left >= right) return;
    int i = left, j = right;
    long pivot = numbers[left];

    while (i <= j) {
        while (numbers[i] < pivot) i++;
        while (numbers[j] > pivot) j--;
        if (i <= j) {
            long temp = numbers[i];
            numbers[i++] = numbers[j];
            numbers[j--] = temp;
        }
    }

    quick_sort(numbers, left, j);
    quick_sort(numbers, i, right);
}

void sort(long *numbers, int n) {
    quick_sort(numbers, 0, n - 1);
}


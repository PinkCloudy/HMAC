#include <iostream>
#include <vector>
#include <algorithm>
#include <omp.h>
#include <chrono>

using namespace std; 
// Hàm trộn hai mảng con đã sắp xếp
void merge(vector<int>& arr, int l, int m, int r) {
    int n1 = m - l + 1;
    int n2 = r - m;
    vector<int> L(n1), R(n2);

    for (int i = 0; i < n1; i++) L[i] = arr[l + i];
    for (int j = 0; j < n2; j++) R[j] = arr[m + 1 + j];

    int i = 0, j = 0, k = l;
    while (i < n1 && j < n2) {
        if (L[i] <= R[j]) arr[k++] = L[i++];
        else arr[k++] = R[j++];
    }
    while (i < n1) arr[k++] = L[i++];
    while (j < n2) arr[k++] = R[j++];
}

// Hàm Merge Sort song song
void parallelMergeSort(vector<int>& arr, int l, int r, int depth) {
    if (l < r) {
        // Ngưỡng dừng: Nếu mảng quá nhỏ (~1000 p tử) hoặc độ sâu quá lớn, chạy tuần tự
        if (depth <= 0 || (r - l) < 1000) {
            int m = l + (r - l) / 2;
            parallelMergeSort(arr, l, m, 0); // depth = 0 để ép chạy tuần tự
            parallelMergeSort(arr, m + 1, r, 0);
            merge(arr, l, m, r);
            return;
        }

        int m = l + (r - l) / 2;

        #pragma omp task shared(arr)
        parallelMergeSort(arr, l, m, depth - 1);

        #pragma omp task shared(arr)
        parallelMergeSort(arr, m + 1, r, depth - 1);

        #pragma omp taskwait // Chờ các task con hoàn thành trước khi merge
        merge(arr, l, m, r);
    }
}

int main() {
    const int N = 1000000; // Sắp xếp 1 triệu phần tử
    vector<int> data(N);
    
    // Khởi tạo dữ liệu ngẫu nhiên
    for (int i = 0; i < N; i++) data[i] = rand() % N;

    cout << "Dang sap xep " << N << " phan tu..." << endl;

    // Bắt đầu đo thời gian
    auto start = chrono::high_resolution_clock::now();

    #pragma omp parallel
    {
        #pragma omp single // Chỉ cần 1 luồng khởi tạo task gốc
        parallelMergeSort(data, 0, N - 1, 4); // Độ sâu task là 4 (tạo ra khoảng 16 tasks lớn)
    }

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> diff = end - start;

    cout << "Thoi gian thuc thi: " << diff.count() << " giay" << endl;

    // Kiểm tra xem đã sắp xếp đúng chưa
    if (is_sorted(data.begin(), data.end())) {
        cout << "Ket qua: Chinh xac!" << endl;
    } else {
        cout << "Ket qua: Co loi." << endl;
    }

    return 0;
}
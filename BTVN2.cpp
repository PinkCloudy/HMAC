#include <iostream>

using namespace std;

// Hàm tìm bậc đa thức 
int tim_bac(int n) {
    int bac = -1;
    while (n > 0) {
        n >>= 1;
        bac++;
    }
    return bac;
}

// Hàm nhân đa thức trong trường GF(2)
int nhan_gf2(int a, int b) {
    int ket_qua = 0;
    for (int i = 0; (b >> i) > 0; i++) {
        if ((b >> i) & 1) {
            ket_qua ^= (a << i);
        }
    }
    return ket_qua;
}

void in_cot(int gia_tri) {
    cout << gia_tri;
    if (gia_tri < 10) cout << "         ";
    else if (gia_tri < 100) cout << "        ";
    else if (gia_tri < 1000) cout << "       ";
    else cout << "      ";
    cout << "| ";
}

// Thuật toán Euclidean mở rộng
void tim_nghich_dao_gf(int a, int m) {
    int r0 = m, r1 = a;
    int v0 = 0, v1 = 1;

    cout << "--- Tim nghich dao cua " << a << " ---" << endl;
    cout << "Thuong (Q) | Du (R)     | He so (V)" << endl;
    cout << "-----------------------------------" << endl;

    while (r1 > 1) {
        int bac0 = tim_bac(r0);
        int bac1 = tim_bac(r1);
        int thuong = 0;
        int tam_du = r0;

        // Phép chia đa thức (XOR)
        for (int i = bac0 - bac1; i >= 0; i--) {
            if ((tam_du >> (i + bac1)) & 1) {
                thuong ^= (1 << i);
                tam_du ^= (r1 << i);
            }
        }
        int v_moi = v0 ^ nhan_gf2(thuong, v1);

        r0 = r1;
        r1 = tam_du;
        v0 = v1;
        v1 = v_moi;

        // In các giá trị trung gian
        in_cot(thuong);
        in_cot(r1);
        cout << v1 << endl;

        if (r1 == 0) {
            cout << "Loi: Khong ton tai nghich dao!" << endl;
            return;
        }
    }

    cout << "==> Nghich dao cuoi cung: " << v1 << endl << endl;
}

int main() {
    // Đa thức tối giản m(x) = x^10 + x^3 + 1 tương ứng số 1033
    int da_thuc_m = 1033;
    
    // Chạy test vector cho a = 523 và b = 1015
    tim_nghich_dao_gf(523, da_thuc_m);
    tim_nghich_dao_gf(1015, da_thuc_m);

    return 0;
}
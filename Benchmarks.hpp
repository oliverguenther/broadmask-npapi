#include <vector>

struct bes_setup_times {
    double setup_time;
    std::vector<double> receiver_setup_times;
    
    int public_key_size;
};


struct bes_encryption_times {
    double enc_time;
    std::vector<double> dec_times;
    
    int ciphertext_size;
};
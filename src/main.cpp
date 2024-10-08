#include "ud_sym_encoder.h"
#include <iostream>

int main(){
    
    std::unique_ptr<dg::ud_sym_encoder::EncoderInterface> encoder = dg::ud_sym_encoder::spawn_encoder("my_secret_should_be_1<<30_in_length", 50);
    std::string test_str = "tomskicus";
    std::string out_str = encoder->decode(encoder->encode(test_str));

    std::cout << out_str << " " << out_str.size();
}
#include "ud_sym_encoder.h"
#include <iostream>
#include <random> 
#include <utility>
#include <functional>

int main(){

    //this is Blank Space by Taylor Swift
    
    //the game is over if the space size == 1u
    //let's see what we mean by that

    //the encoding scheme is called unfair if the next predicting token distribution is skewed, imagine we are decrypting an important message char by char
    //the best possible prediction algorithm is not greater than picking a random secret in the current possible_secret set, and sigma the statistical chances of the next token (proof by contradiction, assume there exists an algorithm chances better than that, it must be referring to a set of possible secrets that is not the current set which is a misimplementation of logic)
    //because of the uniformness of the secret output projection space, we can prove that an optimal encoding algorithm is uniformly distributed

    //Let S be the set of possibile secrets at the current time
    //we are greedy people, for every char, we are decreasing the set size by 1, what does this mean?
    //it means that size(S) - 1 returns the same result, and 1 other guy return 1 unique different result, this breaches the contract of fairness at the point of prediction
    //so for every char, we must decrease the set size -> size(S) / 256, proof by contradiction

    //alright, I was thinking about this again
    //secret -> sub_secret -> token
    //compromise points: sub_secret, secret
    //sub_secret compromised -> token decoded
    //secret compromised -> foreign injections
    //sub_secret is our only weakness
    //for every generated token, we are decreasing one byte of secret trustworthiness (up to subsecret size), and one byte of subsecret trustworthiness
    //this is the base rule of token generation
    //we need to allow the flex_length of subsecret to protect user data, we establish pre-connected secret protocols (before we even communicate, public private asymmetric key pairs dont work)
    //we'll fix some of the fundamentals to integrate this into our system

    //tested + verified for g++-13 main.cpp -O3 -std=c++23
    //I've tried to think of every useful scenerios for asymmetric keys and there's none
    //the fundamental concept of asymmetric is very broken
    //it's possible to decode/decrypt the msg by using the public key - ask AI - don't even argue
    //the fundamental concept of encoding is symmetric and uniform distribution, if it's skewed, it's bad

    std::unique_ptr<dg::ud_sym_encoder::EncoderInterface> encoder = dg::ud_sym_encoder::spawn_encoder("my_secret_should_be_1<<30_in_length"); //this is why this is unbreakable, even by quant computer, what is that? or AI

    auto rand_gen   = std::bind(std::uniform_int_distribution<char>{}, std::mt19937{});
    auto sz_gen     = std::bind(std::uniform_int_distribution<uint8_t>{}, std::mt19937{}); 

    while (true){
        std::string inp(sz_gen(), ' ');
        std::generate(inp.begin(), inp.end(), std::ref(rand_gen));
        std::string out = encoder->decode(encoder->encode(inp));

        if (inp != out){
            std::cout << "mayday" << std::endl;
        }
    }
}
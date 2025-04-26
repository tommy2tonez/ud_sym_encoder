#ifndef __DG_UNIFORM_DISTRIBUTED_SYMMETRIC_ENCODER_H__
#define __DG_UNIFORM_DISTRIBUTED_SYMMETRIC_ENCODER_H__

#include <random>
#include <stdint.h>
#include <stdlib.h>
#include <string>
#include <stdexcept>
#include "compact_serializer.h"
#include <bit>
#include <algorithm>

namespace dg::ud_sym_encoder{

    struct corrupted_format: std::exception{}; 
    struct invalid_argument: std::exception{}; 

    struct EncoderInterface{
        virtual ~EncoderInterface() noexcept = default;
        virtual auto encode(const std::string&) -> std::string = 0;
        virtual auto decode(const std::string&) -> std::string = 0; 
    };

    struct MurMurMessage{
        uint64_t validation_key;
        std::string encoded;

        template <class Reflector>
        void dg_reflect(const Reflector& reflector) const{
            reflector(validation_key, encoded);
        }

        template <class Reflector>
        void dg_reflect(const Reflector& reflector){
            reflector(validation_key, encoded);
        }
    };

    class MurMurEncoder: public virtual EncoderInterface{

        private:

            uint64_t secret; //we are susceptible to same-salt attacks, the secret virtualized space protected by the sub-secret (a.k.a. seed) is exposed, we are now vulnerable with the exposed secret, we can easily reverse engineer the encode, to pass through the integrity decode phase, to avoid this from happening, we must specify the sub-secret space size to protect this secret space size

        public:

            static inline constexpr uint32_t MURMUR_SERIALIZATION_SECRET = 1042927439ULL;

            MurMurEncoder(uint64_t secret) noexcept: secret(secret){}

            auto encode(const std::string& arg) -> std::string{

                uint64_t key    = dg::hasher::murmur_hash(arg.data(), arg.size(), this->secret);
                auto msg        = MurMurMessage{.validation_key = key, 
                                                .encoded        = arg};

                return dg::compact_serializer::integrity_serialize<std::string>(msg, MURMUR_SERIALIZATION_SECRET);
            }

            auto decode(const std::string& arg) -> std::string{

                try{
                    MurMurMessage msg       = dg::compact_serializer::integrity_deserialize<MurMurMessage>(arg, MURMUR_SERIALIZATION_SECRET);
                    uint64_t expected_key   = dg::hasher::murmur_hash(msg.encoded.data(), msg.encoded.size(), this->secret);

                    if (expected_key != msg.validation_key){
                        throw corrupted_format();
                    }

                    return std::string(std::move(msg.encoded));
                } catch (dg::compact_serializer::exception_space::corrupted_format& err){
                    throw corrupted_format();
                } catch (...){
                    std::rethrow_exception(std::current_exception());
                }
            }
    };

    struct Mt19937Message{
        uint64_t salt;
        std::string encoded;

        template <class Reflector>
        void dg_reflect(const Reflector& reflector){
            reflector(salt, encoded);
        }

        template <class Reflector>
        void dg_reflect(const Reflector& reflector) const{
            reflector(salt, encoded);
        }
    };

    using mt19937 = std::mersenne_twister_engine<uint64_t, 64, 312, 156, 31,
                                                 0xb5026f5aa96619e9ULL, 29,
                                                 0x5555555555555555ULL, 17,
                                                 0x71d67fffeda60000ULL, 37,
                                                 0xfff7eee000000000ULL, 43,
                                                 6364136223846793005ULL>;

    //we have problems
    class Mt19937Encoder: public virtual EncoderInterface{

        private:

            std::string secret;
            mt19937 salt_randgen;
            
        public:


            Mt19937Encoder(std::string secret,
                           mt19937 salt_randgen) noexcept: secret(std::move(secret)),
                                                           salt_randgen(std::move(salt_randgen)){}

            static inline constexpr uint32_t MT19937_SERIALIZATION_SECRET = 1422722760ULL;

            auto encode(const std::string& arg) -> std::string{
                
                uint64_t salt       = this->salt_randgen();
                uint64_t subsecret  = this->randomizer_seed(this->secret, salt);
                auto randomizer     = mt19937{subsecret};
                auto encoded        = std::string(arg.size(), ' ');

                for (size_t i = 0u; i < arg.size(); ++i){
                    encoded[i] = this->byte_encode(arg[i], randomizer);
                }

                return this->serialize(Mt19937Message{.salt     = salt,
                                                      .encoded  = std::move(encoded)}); 
            }

            auto decode(const std::string& arg) -> std::string{

                Mt19937Message msg  = this->deserialize(arg);                
                uint64_t subsecret  = this->randomizer_seed(this->secret, msg.salt);
                auto randomizer     = mt19937{subsecret};
                auto decoded        = std::string(msg.encoded.size(), ' ');

                for (size_t i = 0u; i < msg.encoded.size(); ++i){
                    decoded[i] = this->byte_decode(msg.encoded[i], randomizer);
                }

                return decoded;
            }
        
        private:

            auto randomizer_seed(const std::string& secret, uint64_t salt) -> uint64_t{
                
                std::string ss(dg::trivial_serializer::size(salt), ' ');
                dg::trivial_serializer::serialize_into(ss.data(), salt);
                std::string cat = secret + ss; 

                return dg::hasher::murmur_hash(cat.data(), cat.size());
            }

            template <class Randomizer>
            auto get_byte_dict(Randomizer& randomizer) -> std::vector<uint8_t>{
                
                std::vector<uint8_t> rs(256);
                std::iota(rs.begin(), rs.end(), 0u);

                for (size_t i = 0u; i < 256; ++i){
                    size_t lhs_idx = static_cast<size_t>(randomizer()) % 256;
                    size_t rhs_idx = static_cast<size_t>(randomizer()) % 256;
                    std::swap(rs[lhs_idx], rs[rhs_idx]);
                }

                return rs;
            }

            template <class Randomizer>
            auto byte_encode(char key, Randomizer& randomizer) -> char{

                std::vector<uint8_t> dict = this->get_byte_dict(randomizer);
                return std::bit_cast<char>(dict[std::bit_cast<uint8_t>(key)]);
            }

            template <class Randomizer>
            auto byte_decode(char value, Randomizer& randomizer) -> char{
                
                std::vector<uint8_t> dict = this->get_byte_dict(randomizer);
                uint8_t key = std::distance(dict.begin(), std::find(dict.begin(), dict.end(), std::bit_cast<uint8_t>(value)));

                return std::bit_cast<char>(key);
            }

            auto serialize(const Mt19937Message& msg) -> std::string{

                return dg::compact_serializer::integrity_serialize<std::string>(msg, MT19937_SERIALIZATION_SECRET); 
            }

            auto deserialize(const std::string& bstream) -> Mt19937Message{

                return dg::compact_serializer::integrity_deserialize<Mt19937Message>(bstream, MT19937_SERIALIZATION_SECRET);             
            }
    };

    class DoubleEncoder: public virtual EncoderInterface{

        private:

            std::unique_ptr<EncoderInterface> first_encoder;
            std::unique_ptr<EncoderInterface> second_encoder;
        
        public:

            DoubleEncoder(std::unique_ptr<EncoderInterface> first_encoder,
                          std::unique_ptr<EncoderInterface> second_encoder) noexcept: first_encoder(std::move(first_encoder)),
                                                                                      second_encoder(std::move(second_encoder)){}
            
            auto encode(const std::string& msg) -> std::string{
                
                return this->second_encoder->encode(this->first_encoder->encode(msg));
            }

            auto decode(const std::string& msg) -> std::string{

                return this->first_encoder->decode(this->second_encoder->decode(msg));
            }
    };
    
    auto spawn_encoder(const std::string& secret) -> std::unique_ptr<EncoderInterface>{

        uint64_t uint_secret = dg::hasher::murmur_hash(secret.data(), secret.size());

        std::unique_ptr<EncoderInterface> integrity_encoder = std::make_unique<MurMurEncoder>(uint_secret);
        std::unique_ptr<EncoderInterface> unif_dist_encoder = std::make_unique<Mt19937Encoder>(secret, mt19937{}); 
        std::unique_ptr<EncoderInterface> combined_encoder  = std::make_unique<DoubleEncoder>(std::move(integrity_encoder), std::move(unif_dist_encoder));

        return combined_encoder;
    }
}

#endif
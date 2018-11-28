#include <enulib/transaction.hpp>
#include <enulib/crypto.h>
#include <enulib/types.h>
#include <enulib/currency.hpp>

#define ENU_SYMBOL S(4, ENU)

using namespace enumivo;
using namespace std;

//for display
template <typename CharT>
static std::string to_hex(const CharT *d, uint32_t s)
{
    std::string r;
    const char *to_hex = "0123456789abcdef";
    uint8_t *c = (uint8_t *)d;
    for (uint32_t i = 0; i < s; ++i)
    {
        (r += to_hex[(c[i] >> 4)]) += to_hex[(c[i] & 0x0f)];
    }
    return r;
}

// Copied from https://github.com/bitcoin/bitcoin

/** All alphanumeric characters except for "0", "I", "O", and "l" */
static const char *pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static const int8_t mapBase58[256] = {
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    16,
    -1,
    17,
    18,
    19,
    20,
    21,
    -1,
    22,
    23,
    24,
    25,
    26,
    27,
    28,
    29,
    30,
    31,
    32,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    33,
    34,
    35,
    36,
    37,
    38,
    39,
    40,
    41,
    42,
    43,
    -1,
    44,
    45,
    46,
    47,
    48,
    49,
    50,
    51,
    52,
    53,
    54,
    55,
    56,
    57,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
};

bool DecodeBase58(const char *psz, std::vector<unsigned char> &vch)
{
    // Skip leading spaces.
    while (*psz && isspace(*psz))
        psz++;
    // Skip and count leading '1's.
    int zeroes = 0;
    int length = 0;
    while (*psz == '1')
    {
        zeroes++;
        psz++;
    }
    // Allocate enough space in big-endian base256 representation.
    int size = strlen(psz) * 733 / 1000 + 1; // log(58) / log(256), rounded up.
    std::vector<unsigned char> b256(size);
    // Process the characters.
    static_assert(sizeof(mapBase58) / sizeof(mapBase58[0]) == 256, "mapBase58.size() should be 256"); // guarantee not out of range
    while (*psz && !isspace(*psz))
    {
        // Decode base58 character
        int carry = mapBase58[(uint8_t)*psz];
        if (carry == -1) // Invalid b58 character
            return false;
        int i = 0;
        for (std::vector<unsigned char>::reverse_iterator it = b256.rbegin(); (carry != 0 || i < length) && (it != b256.rend()); ++it, ++i)
        {
            carry += 58 * (*it);
            *it = carry % 256;
            carry /= 256;
        }
        assert(carry == 0);
        length = i;
        psz++;
    }
    // Skip trailing spaces.
    while (isspace(*psz))
        psz++;
    if (*psz != 0)
        return false;
    // Skip leading zeroes in b256.
    std::vector<unsigned char>::iterator it = b256.begin() + (size - length);
    while (it != b256.end() && *it == 0)
        it++;
    // Copy result into output vector.
    vch.reserve(zeroes + (b256.end() - it));
    vch.assign(zeroes, 0x00);
    while (it != b256.end())
        vch.push_back(*(it++));
    return true;
}

bool decode_base58(const string &str, vector<unsigned char> &vch)
{
    return DecodeBase58(str.c_str(), vch);
}

class RedEnvelope : public enumivo::contract
{
  public:
    RedEnvelope(account_name self) : enumivo::contract(self),
                                     _global(_self, _self),
                                     _envelopes(_self, _self)
    {
    }

    // @abi action
    void get(const uint64_t envelope_id, const account_name user, const signature &sig);

    void transfer(const account_name from, const account_name to, const asset quantity, const std::string memo);

    // @abi action
    void hop(const uint64_t envelope_id, const account_name user, const signature &sig, const public_key &pk);

    // @abi action
    void reveal(const uint64_t envelope_id, const account_name user, const signature &sig, const public_key &pk);

    // @abi action
    void reset();

    // @abi action
    void release(const uint64_t envelope_id);

  private:
    struct this_public_key
    {
        uint8_t type;
        array<unsigned char, 33> data;
    };
    this_public_key getPublicKey(const string public_key_str)
    {
        enumivo_assert(public_key_str.length() == 53, "Length of publik key should be 53");

        string pubkey_prefix("ENU");
        auto result = mismatch(pubkey_prefix.begin(), pubkey_prefix.end(), public_key_str.begin());
        enumivo_assert(result.first == pubkey_prefix.end(), "Public key should be prefix with ENU");
        auto base58substr = public_key_str.substr(pubkey_prefix.length());

        vector<unsigned char> vch;
        enumivo_assert(decode_base58(base58substr, vch), "Decode pubkey failed");
        enumivo_assert(vch.size() == 37, "Invalid public key");

        array<unsigned char, 33> pubkey_data;
        copy_n(vch.begin(), 33, pubkey_data.begin());

        checksum160 check_pubkey;
        ripemd160(reinterpret_cast<char *>(pubkey_data.data()), 33, &check_pubkey);
        enumivo_assert(memcmp(&check_pubkey.hash, &vch.end()[-4], 4) == 0, "invalid public key");

        this_public_key pk = {
            .type = 0,
            .data = pubkey_data,
        };

        return pk;
    }

    void SplitString(const std::string &s, std::vector<std::string> &v, const std::string &c)
    {
        std::string::size_type pos1, pos2;
        pos2 = s.find(c);
        pos1 = 0;
        while (std::string::npos != pos2)
        {
            v.push_back(s.substr(pos1, pos2 - pos1));

            pos1 = pos2 + c.size();
            pos2 = s.find(c, pos1);
        }
        if (pos1 != s.length())
            v.push_back(s.substr(pos1));
    }

    string int2str(uint64_t x)
    {
        string tmp(""), ans("");
        while (x > 0)
        {
            tmp += (x % 10) + 48;
            x /= 10;
        }
        for (int i = tmp.size() - 1; i >= 0; i--)
        {
            ans += tmp[i];
        }
        return ans;
    }

    uint64_t _next_id()
    {
        auto gl_itr = _global.begin();
        if (gl_itr == _global.end())
        {
            gl_itr = _global.emplace(_self, [&](auto &gl) {
                gl.global_id = 0;
                gl.next_id = 0;
            });
        }
        _global.modify(gl_itr, 0, [&](auto &gl) {
            gl.next_id++;
        });
        return gl_itr->next_id;
    }

    // @abi table global i64
    struct global
    {
        uint64_t global_id;
        uint64_t next_id;
        uint64_t primary_key() const { return global_id; }
        ENULIB_SERIALIZE(global, (global_id)(next_id))
    };

    typedef enumivo::multi_index<N(global), global> global_index;
    global_index _global;

    // @abi table envelopes i64
    struct envelopes
    {
        uint64_t envelope_id;
        uint8_t type;
        account_name creator;
        string words;
        string public_key;
        asset total_quantity;
        asset rest_quantity;
        uint64_t total_number;
        uint64_t rest_number;
        uint64_t create_time;
        uint64_t expire_time;
        uint64_t primary_key() const { return envelope_id; }
        ENULIB_SERIALIZE(envelopes, (envelope_id)(type)(creator)(words)(public_key)(total_quantity)(rest_quantity)(total_number)(rest_number)(create_time)(expire_time))
    };

    typedef enumivo::multi_index<N(envelopes), envelopes> envelopes_index;
    envelopes_index _envelopes;
};

#define ENUMIVO_ABI_EX(TYPE, MEMBERS)                                                                                      \
    extern "C"                                                                                                             \
    {                                                                                                                      \
        void apply(uint64_t receiver, uint64_t code, uint64_t action)                                                      \
        {                                                                                                                  \
            if (action == N(onerror))                                                                                      \
            {                                                                                                              \
                enumivo_assert(code == N(enumivo), "onerror action's are only valid from the \"enumivo\" system account"); \
            }                                                                                                              \
            auto self = receiver;                                                                                          \
            if ((code == self && action != N(transfer)) || (code == N(enu.token) && action == N(transfer)))                \
            {                                                                                                              \
                TYPE thiscontract(self);                                                                                   \
                switch (action)                                                                                            \
                {                                                                                                          \
                    ENUMIVO_API(TYPE, MEMBERS)                                                                             \
                }                                                                                                          \
            }                                                                                                              \
        }                                                                                                                  \
    }

ENUMIVO_ABI_EX(RedEnvelope, (transfer)(get)(reveal)(hop)(reset)(release))

#include "redenvelope.hpp"

class RedEnvelope : public enumivo::contract
{
  public:
    RedEnvelope(account_name self) : enumivo::contract(self)
    {
    }

    // @abi action
    void get(const account_name user, /* const checksum256 &hashData, */ const signature &sig)
    {
        auto pk = getPublicKey("ENU7q4gy7XW72NkqwQc43BMjbs6zBsL8428T53tYZyKVWEGJcjJc9");
        //send defer action
        enumivo::transaction txn{};
        txn.actions.emplace_back(
            enumivo::permission_level(_self, N(active)),
            _self,
            N(jump),
            std::make_tuple(user, sig, pk));
        txn.send(0, _self, false);

        /* action(permission_level{_self, N(active)},
               _self, N(reveal),
               std::make_tuple(user, sig, pk))
            .send(); */
    }

    void transfer(const account_name from, const account_name to, const asset quantity, const std::string memo)
    {
        /* vector<string> splits;
        SplitString(memo, splits, ":"); 
        "ENU7q4gy7XW72NkqwQc43BMjbs6zBsL8428T53tYZyKVWEGJcjJc9"*/
    }

    // @abi action
    void jump(const account_name user, const signature &sig, const public_key &pk)
    {
        require_auth(_self);
        //send defer action
        enumivo::transaction txn{};
        txn.actions.emplace_back(
            enumivo::permission_level(_self, N(active)),
            _self,
            N(reveal),
            std::make_tuple(user, sig, pk));
        txn.send(0, _self, false);
    }

    // @abi action
    void reveal(const account_name user, /* const checksum256 &hashData, */ const signature &sig, const public_key &pk)
    {
        auto user_name = (name{user}).to_string();
        const char *mixedChar = user_name.c_str();

        checksum256 digest;
        sha256((char *)mixedChar, user_name.length(), &digest);

        /* assert_sha256((char *)mixedChar, user_name.length(), &hashData); */

        auto hex_public_key_str = to_hex(&pk, sizeof(pk));
        print("input public key:");
        print(hex_public_key_str.c_str());
        print("\n");

        public_key new_pk;
        recover_key(&digest, (char *)&sig, sizeof(sig), (char *)&new_pk, sizeof(new_pk));
        auto new_hex_public_key_str = to_hex(&new_pk, sizeof(new_pk));

        print("recover public key:");
        print(new_hex_public_key_str.c_str());
        print("\n");

        assert_recover_key(&digest, (const char *)&sig, sizeof(sig), (const char *)&pk, sizeof(pk));
        print("VALID");
    }

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

ENUMIVO_ABI_EX(RedEnvelope, (transfer)(get)(reveal)(jump))
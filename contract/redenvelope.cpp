#include "redenvelope.hpp"

void RedEnvelope::get(const uint64_t envelope_id, const account_name user, const signature &sig)
{
    //check user name
    enumivo_assert(is_account(user), "user should be valid account.");

    auto itr = _envelopes.find(envelope_id);
    enumivo_assert(itr != _envelopes.end() && itr->envelope_id == envelope_id, "envelope not exsit!");

    auto logs = itr->logs;

    for (int i = 0; i < logs.size(); i++)
    {
        enumivo_assert(user != logs[i].user, "this user has already get this envelope!");
    }

    auto pk = getPublicKey(itr->public_key);

    string create_account_str = "";

    switch (itr->type)
    {
        //normal
    case 1:
        //inline action
        action(permission_level{_self, N(active)}, _self, N(reveal), std::make_tuple(envelope_id, user, sig, pk, create_account_str))
            .send();
        break;
    case 2:
    {
        //send defer action
        enumivo::transaction txn{};
        txn.actions.emplace_back(
            enumivo::permission_level(_self, N(active)),
            _self,
            N(hop),
            std::make_tuple(envelope_id, user, sig, pk));
        txn.send(_next_id(), _self, false);
    }
    break;

    default:
        enumivo_assert(false, "type error!");
    }
}

void RedEnvelope::transfer(const account_name from, const account_name to, const asset quantity, const string memo)
{
    if (from == _self || to != _self)
    {
        return;
    }

    vector<string> splits;
    SplitString(memo, splits, "|");
    uint8_t type = atoi((splits[0]).c_str());
    //print("\nid:");
    //print(splits[1]);
    /* uint64_t envelope_id;
    std::istringstream iss(splits[1]);
    iss >> envelope_id; */
    uint64_t envelope_id = std::stoull((splits[1]).c_str());
    //print("\nid:");
    //print(envelope_id);
    uint8_t num = atoi((splits[2]).c_str());
    string words = splits[3];
    string public_key = splits[4];

    enumivo_assert(quantity.symbol == ENU_SYMBOL, "accept ENU only");
    enumivo_assert(quantity.is_valid(), "transfer invalid quantity");

    enumivo_assert(quantity.amount >= 10000, "amount must >= 1 ENU");
    enumivo_assert(num <= 100, "envolopes number must <= 100");
    enumivo_assert(num >= 1, "red envelope numbers must >= 1");

    //enumivo_assert(quantity.amount <= MAX, "amount must <= 2000 ENU");

    //auto id = _next_id();

    enumivo_assert(_envelopes.find(envelope_id) == _envelopes.end(), "envelope already exsit!");

    /* vector<asset> quantities;
    if (type == 2)
    {
        int i = 0;
        auto left_amount = quantity.amount - num;
        enumivo_assert(left_amount > 0, "amount error!");
        auto left_number = num;
        while (i < num - 1)
        {
            auto random_number = _random(from, i, 300);
            print("\nrandom:");
            print(int2str(random_number).c_str());
            uint64_t result = random_number / 100 * left_amount / left_number;
            if (result > left_amount)
            {
                result = left_amount;
            }
            quantities.push_back(asset(result + 1, ENU_SYMBOL));
            left_amount -= result;
            left_number--;
            i++;
        }
        quantities.push_back(asset(left_amount + 1, ENU_SYMBOL));
    }; */

    _envelopes.emplace(_self, [&](auto &e) {
        e.envelope_id = envelope_id;
        e.type = type;
        e.creator = from;
        e.words = words;
        e.public_key = public_key;
        e.total_quantity = quantity;
        e.rest_quantity = quantity;
        e.total_number = num;
        e.rest_number = num;
        e.create_time = now();
        e.expire_time = now() + 24 * 60 * 60; //1day
        //e.quantities = quantities;
    });

    //send defer action, cancel after 24 hours
    enumivo::transaction txn{};
    txn.actions.emplace_back(
        enumivo::permission_level(_self, N(active)),
        _self,
        N(release),
        std::make_tuple(envelope_id));
    txn.delay_sec = 60 * 60 * 24;
    txn.send(_next_id(), _self, false);
}

void RedEnvelope::hop(const uint64_t envelope_id, const account_name user, const signature &sig, const public_key &pk)
{
    require_auth(_self);
    //send defer action
    enumivo::transaction txn{};
    txn.actions.emplace_back(
        enumivo::permission_level(_self, N(active)),
        _self,
        N(reveal),
        std::make_tuple(envelope_id, user, sig, pk, string("")));
    txn.send(_next_id(), _self, false);
}

void RedEnvelope::reveal(const uint64_t envelope_id, const account_name user, const signature &sig, const public_key &pk, const string create_account_str)
{
    require_auth(_self);

    auto itr = _envelopes.find(envelope_id);
    enumivo_assert(itr != _envelopes.end() && itr->envelope_id == envelope_id, "envelope not exsit!");

    uint64_t create_time = itr->create_time;

    auto user_name = (name{user}).to_string();
    auto raw_data = user_name + int2str(envelope_id) + int2str(create_time);

    //print("\nraw_data:");
    //print(raw_data);
    const char *mixedChar = raw_data.c_str();

    checksum256 digest;
    sha256((char *)mixedChar, raw_data.length(), &digest);

    //print ----
    /* auto hex_public_key_str = to_hex(&pk, sizeof(pk));
    print("\ninput public key:");
    print(hex_public_key_str.c_str());
    print("\n");

    public_key new_pk;
    recover_key(&digest, (char *)&sig, sizeof(sig), (char *)&new_pk, sizeof(new_pk));
    auto new_hex_public_key_str = to_hex(&new_pk, sizeof(new_pk));

    print("\nrecover public key:");
    print(new_hex_public_key_str.c_str());
    print("\n"); */
    //print ----

    assert_recover_key(&digest, (const char *)&sig, sizeof(sig), (const char *)&pk, sizeof(pk));

    auto total_amount = itr->total_quantity.amount;
    auto rest_amount = itr->rest_quantity.amount;
    auto total_number = itr->total_number;
    auto rest_number = itr->rest_number;
    string creator = (name{itr->creator}).to_string();
    string words = itr->words;
    auto logs = itr->logs;
    uint64_t this_amount;

    enumivo_assert(rest_amount > 0 && rest_number > 0, "this envelope is empty!");

    switch (itr->type)
    {
        //normal
    case 1:
        this_amount = total_amount / total_number;
        rest_amount = rest_amount - this_amount;
        rest_number -= 1;
        break;

        //random
    case 2:
    {
        if (rest_number == 1)
        {
            this_amount = rest_amount;
        }
        else
        {
            uint64_t min = 1;
            uint64_t max = rest_amount / rest_number * 2;
            auto r = _random(user, envelope_id, 100);
            //print("\nrandom:");
            //print(int2str(r).c_str());
            this_amount = max * r / 100;
            if (this_amount < min)
            {
                this_amount = min;
            }
        }
        rest_amount = rest_amount - this_amount;
        rest_number -= 1;
    }
    break;

    default:
        enumivo_assert(false, "type error!");
    }

    //string memo = "get red envelope from " + creator + "," + words;

    envelope_log log = {
        .user = user,
        .quantity = asset(this_amount, ENU_SYMBOL),
    };

    logs.push_back(log);

    _envelopes.modify(itr, 0, [&](auto &e) {
        e.rest_quantity = asset(rest_amount, ENU_SYMBOL);
        e.rest_number = rest_number;
        e.logs = logs;
    });

    account_name transfer_to;
    string memo;
    if (create_account_str == "")
    {
        memo = "get red envelope from " + creator + "," + words;
        transfer_to = user;
    }
    else
    {
        memo = create_account_str;
        enumivo_assert(this_amount >= 10000, "create account need at least 1 ENU!");
        transfer_to = N(enu);
    }

    //send
    action(permission_level{_self, N(active)}, N(enu.token), N(transfer), std::make_tuple(_self, transfer_to, asset(this_amount, ENU_SYMBOL), memo))
        .send();

    //release when empty
    /* if (rest_number == 0)
    {
        //send defer action, release after 1 hours
        enumivo::transaction txn{};
        txn.actions.emplace_back(
            enumivo::permission_level(_self, N(active)),
            _self,
            N(release),
            std::make_tuple(envelope_id));
        txn.delay_sec = 60 * 60;
        txn.send(_next_id(), _self, false);
    } */
}

void RedEnvelope::newaccount(const uint64_t envelope_id, const account_name user, const signature &sig, const string public_key_str)
{
    //check user name
    enumivo_assert(!is_account(user), "account already exsit!");

    auto itr = _envelopes.find(envelope_id);
    enumivo_assert(itr != _envelopes.end() && itr->envelope_id == envelope_id, "envelope not exsit!");
    enumivo_assert(itr->type == 1, "newaccount only support normal type!");

    auto pk = getPublicKey(itr->public_key);

    string create_account_str = name{user}.to_string() + ":" + public_key_str;
    //print("\ncreate account:");
    //print(create_account_str);
    action(permission_level{_self, N(active)}, _self, N(reveal), std::make_tuple(envelope_id, user, sig, pk, create_account_str))
        .send();
}

void RedEnvelope::reset()
{
    require_auth(_self);
    auto i = 0;
    auto itr = _envelopes.begin();
    while (itr != _envelopes.end())
    {
        i++;
        _envelopes.erase(itr);
        itr = _envelopes.begin();
    }
    //print("\nenvelope number:");
    //print(i);
}

void RedEnvelope::withdraw(const uint64_t envelope_id)
{
    auto itr = _envelopes.find(envelope_id);
    enumivo_assert(itr != _envelopes.end(), "can not find the envelope");
    require_auth(itr->creator);
    action(permission_level{_self, N(active)}, _self, N(release), std::make_tuple(envelope_id))
        .send();
}

void RedEnvelope::release(const uint64_t envelope_id)
{
    require_auth(_self);

    auto itr = _envelopes.find(envelope_id);
    enumivo_assert(itr != _envelopes.end(), "can not find the envelope");

    //print("\nrest_quantity");
    //print(itr->rest_quantity);
    if (itr->rest_quantity.amount > 0)
    {
        action(permission_level{_self, N(active)}, N(enu.token), N(transfer), std::make_tuple(_self, itr->creator, itr->rest_quantity, string("return red envelope")))
            .send();
    }

    _envelopes.erase(itr);
}
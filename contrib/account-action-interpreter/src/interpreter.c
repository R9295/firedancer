/* Appended to solana-llvm-compiler's pinned Solana ABI prelude.
 * Instruction wire format and error codes are documented in README.md.
 * Input account metadata comes from the runtime. Action operands are untrusted.
 */

#define ERR_MALFORMED       ((uint64_t)0xAC0101)
#define ERR_OPCODE          ((uint64_t)0xAC0102)
#define ERR_ACCOUNT         ((uint64_t)0xAC0103)
#define ERR_READONLY        ((uint64_t)0xAC0104)
#define ERR_OWNER           ((uint64_t)0xAC0105)
#define ERR_BOUNDS          ((uint64_t)0xAC0106)
#define ERR_ARITHMETIC      ((uint64_t)0xAC0107)
#define ERR_RESIZE          ((uint64_t)0xAC0108)
#define ERR_NONZERO_DATA    ((uint64_t)0xAC0109)
#define ERR_LOADER_CPI      ((uint64_t)0xAC010A)
#define ERR_EXECUTABLE      ((uint64_t)0xAC010B)
#define MAX_DATA_LENGTH     ((uint64_t)(10 * 1024 * 1024))
#define MAX_ACTIONS         ((uint64_t)256)
#define MAX_READ_BYTES      ((uint64_t)512)
#define RESULT_HEADER_LEN   ((uint64_t)20)

typedef struct {
    uint8_t opcode;
    uint8_t account;
    uint16_t len;
    const uint8_t *payload;
} ActionFrame;

/* Wire operands need not be aligned. Do not cast them to integer pointers. */
static uint64_t read_le(const uint8_t *bytes, uint64_t len) {
    uint64_t result = 0;
    for (uint64_t i = 0; i < len; i++) {
        result |= ((uint64_t)bytes[i]) << (8 * i);
    }
    return result;
}

static void write_le(uint8_t *bytes, uint64_t value, uint64_t len) {
    for (uint64_t i = 0; i < len; i++) {
        bytes[i] = (uint8_t)(value >> (8 * i));
    }
}

static _Bool keys_equal(const SolPubkey *a, const SolPubkey *b) {
    for (uint64_t i = 0; i < 32; i++) {
        if (a->x[i] != b->x[i]) {
            return 0;
        }
    }
    return 1;
}

static uint64_t can_mutate(const SolParameters *params, const SolAccountInfo *account) {
    if (!account->is_writable) {
        return ERR_READONLY;
    }
    if (!keys_equal(account->owner, params->program_id)) {
        return ERR_OWNER;
    }
    return 0;
}

static uint64_t validate_payload(const ActionFrame *action) {
    uint64_t expected = 0;
    switch (action->opcode) {
        case 0: case 1: case 3: case 4: case 8:
        case 11: case 13: case 14:
            break;
        case 2: case 9: case 10:
            expected = 8;
            break;
        case 5:
            return action->len >= 4 ? 0 : ERR_MALFORMED;
        case 6: case 7:
            expected = 4;
            break;
        case 12:
            expected = 32;
            break;
        default:
            return ERR_OPCODE;
    }
    return action->len == expected ? 0 : ERR_MALFORMED;
}

static uint64_t resize_account(
    SolParameters *params,
    const uint64_t *original_lengths,
    uint64_t index,
    uint64_t new_len
) {
    SolAccountInfo *account = &params->ka[index];
    uint64_t error = can_mutate(params, account);
    if (error) {
        return error;
    }
    /* This is the capacity supplied at invocation entry, not the length
     * produced by the previous action. Repeated grows cannot extend it. */
    if (new_len > MAX_DATA_LENGTH ||
        new_len > original_lengths[index] + MAX_PERMITTED_DATA_INCREASE_) {
        return ERR_RESIZE;
    }
    if (new_len > account->data_len) {
        memset(account->data + account->data_len, 0, new_len - account->data_len);
    }
    /* Standard aligned Solana ABI stores a u64 length immediately before
     * data. No writes go outside the runtime's original realloc capacity. */
    *((uint64_t *)(account->data - sizeof(uint64_t))) = new_len;
    /* SolAccountInfo holds data_len by value. Refresh every shallow alias. */
    for (uint64_t i = 0; i < params->ka_num; i++) {
        if (params->ka[i].data == account->data) {
            params->ka[i].data_len = new_len;
        }
    }
    return 0;
}

static uint64_t apply_action(
    SolParameters *params,
    const uint64_t *original_lengths,
    const ActionFrame *action,
    uint8_t *result,
    uint64_t *result_len
) {
    uint64_t error = validate_payload(action);
    if (error) {
        return error;
    }
    if ((uint64_t)action->account >= params->ka_num) {
        return ERR_ACCOUNT;
    }
    SolAccountInfo *account = &params->ka[action->account];
    uint64_t offset;
    uint64_t amount;
    uint64_t balance;
    switch (action->opcode) {
        case 0: /* read_address */
            memcpy(result, account->key->x, 32);
            *result_len = 32;
            return 0;
        case 1: /* read_lamports */
            write_le(result, *account->lamports, 8);
            *result_len = 8;
            return 0;
        case 2: /* read_data */
            offset = read_le(action->payload, 4);
            amount = read_le(action->payload + 4, 4);
            if (amount > MAX_READ_BYTES || offset > account->data_len ||
                amount > account->data_len - offset) {
                return ERR_BOUNDS;
            }
            memcpy(result, account->data + offset, amount);
            *result_len = amount;
            return 0;
        case 3: /* read_owner */
            memcpy(result, account->owner->x, 32);
            *result_len = 32;
            return 0;
        case 4: /* read_executable */
            result[0] = account->executable ? 1 : 0;
            *result_len = 1;
            return 0;
        case 5: /* write_data */
            error = can_mutate(params, account);
            if (error) {
                return error;
            }
            offset = read_le(action->payload, 4);
            amount = action->len - 4;
            if (offset > account->data_len || amount > account->data_len - offset) {
                return ERR_BOUNDS;
            }
            memcpy(account->data + offset, action->payload + 4, amount);
            return 0;
        case 6: /* resize_grow: amount is a delta */
            amount = read_le(action->payload, 4);
            if (amount > (~(uint64_t)0) - account->data_len) {
                return ERR_ARITHMETIC;
            }
            return resize_account(params, original_lengths, action->account,
                                  account->data_len + amount);
        case 7: /* resize_shrink: amount is a delta */
            amount = read_le(action->payload, 4);
            if (amount > account->data_len) {
                return ERR_BOUNDS;
            }
            return resize_account(params, original_lengths, action->account,
                                  account->data_len - amount);
        case 8: /* resize_zero */
            return resize_account(params, original_lengths, action->account, 0);
        case 9: /* credit_lamports: balance checked by runtime at instruction exit */
            if (!account->is_writable) {
                return ERR_READONLY;
            }
            amount = read_le(action->payload, 8);
            balance = *account->lamports;
            if (amount > (~(uint64_t)0) - balance) {
                return ERR_ARITHMETIC;
            }
            *account->lamports = balance + amount;
            return 0;
        case 10: /* debit_lamports */
            error = can_mutate(params, account);
            if (error) {
                return error;
            }
            amount = read_le(action->payload, 8);
            balance = *account->lamports;
            if (amount > balance) {
                return ERR_ARITHMETIC;
            }
            *account->lamports = balance - amount;
            return 0;
        case 11: /* zero_lamports: caller must balance this with credits */
            error = can_mutate(params, account);
            if (error) {
                return error;
            }
            *account->lamports = 0;
            return 0;
        case 12: /* reassign_owner */
            error = can_mutate(params, account);
            if (error) {
                return error;
            }
            for (uint64_t i = 0; i < account->data_len; i++) {
                if (account->data[i] != 0) {
                    return ERR_NONZERO_DATA;
                }
            }
            memcpy(account->owner->x, action->payload, 32);
            return 0;
        case 13:
            /* Loader-v3 DeployWithMaxDataLen is not CPI-allowed. Upgrading or
             * closing a program is a different operation, not a substitute. */
            return ERR_LOADER_CPI;
        case 14:
            /* The runtime skips executable during account ABI writeback.
             * Editing its local copy would falsely report a persistent change. */
            return ERR_EXECUTABLE;
    }
    return ERR_OPCODE;
}

static void emit_result(
    uint8_t *result,
    uint64_t step,
    const ActionFrame *action,
    uint64_t status,
    uint64_t result_len
) {
    result[0] = 'A'; result[1] = 'C'; result[2] = 'R'; result[3] = '1';
    write_le(result + 4, step, 4);
    result[8] = action->opcode;
    result[9] = action->account;
    write_le(result + 10, status, 8);
    write_le(result + 18, result_len, 2);
    SolBytes slice = { .addr = result, .len = RESULT_HEADER_LEN + result_len };
    sol_log_data(&slice, 1);
    sol_set_return_data(result, slice.len);
}

extern uint64_t entrypoint(const uint8_t *input) {
    SolParameters params = (SolParameters){0};
    if (!log_accounts_deserialize(input, &params)) {
        return ERR_MALFORMED;
    }
    uint8_t result[RESULT_HEADER_LEN + MAX_READ_BYTES];
    ActionFrame action = { .opcode = 255, .account = 255, .len = 0, .payload = 0 };
    sol_set_return_data(result, 0);
    if (params.data_len < 4 || params.data[0] != 'A' || params.data[1] != 'C' ||
        params.data[2] != 'I' || params.data[3] != '1') {
        emit_result(result, 0, &action, ERR_MALFORMED, 0);
        return ERR_MALFORMED;
    }
    uint64_t *original_lengths = 0;
    if (params.ka_num) {
        original_lengths = (uint64_t *)heap_alloc(params.ka_num * sizeof(uint64_t), 8);
        if (!original_lengths) {
            return ERR_MALFORMED;
        }
        for (uint64_t i = 0; i < params.ka_num; i++) {
            original_lengths[i] = params.ka[i].data_len;
        }
    }
    uint64_t position = 4;
    uint64_t step = 0;
    while (position < params.data_len) {
        action.opcode = 255;
        action.account = 255;
        if (step >= MAX_ACTIONS || params.data_len - position < 4) {
            emit_result(result, step, &action, ERR_MALFORMED, 0);
            return ERR_MALFORMED;
        }
        action.opcode = params.data[position];
        action.account = params.data[position + 1];
        action.len = (uint16_t)read_le(params.data + position + 2, 2);
        position += 4;
        if ((uint64_t)action.len > params.data_len - position) {
            emit_result(result, step, &action, ERR_MALFORMED, 0);
            return ERR_MALFORMED;
        }
        action.payload = params.data + position;
        position += action.len;
        uint64_t result_len = 0;
        uint64_t status = apply_action(&params, original_lengths, &action,
                                      result + RESULT_HEADER_LEN, &result_len);
        emit_result(result, step, &action, status, result_len);
        if (status) {
            return status;
        }
        step++;
    }
    return 0;
}

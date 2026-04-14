from math import gcd


def _validate_keys(a, b):
    """验证仿射密码的密钥a和b是否合法"""
    if not isinstance(a, int) or not isinstance(b, int):
        raise TypeError("密钥a和b必须为整数。")
    if gcd(a, 26) != 1:
        raise ValueError(
            f"密钥a={a}与26不互质(gcd={gcd(a, 26)})，"
            f"a必须与26互质才能保证加解密的唯一性。"
            f"有效的a值为: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25"
        )


def _validate_text(text, param_name):
    """验证输入文本是否合法"""
    if not isinstance(text, str):
        raise TypeError(f"{param_name}必须为字符串，但收到了{type(text).__name__}类型。")
    if len(text) == 0:
        raise ValueError(f"{param_name}不能为空字符串。")
    if not any(ch.isalpha() for ch in text):
        raise ValueError(
            f"{param_name}中必须包含至少一个英文字母，"
            f"但'{text}'中没有找到任何字母。"
        )


def affine_encrypt(plaintext, a, b):
    """仿射加密函数

    参数:
        plaintext: 待加密的明文字符串，必须包含至少一个英文字母。
                   非字母字符将保持不变。
        a: 密钥a，必须为与26互质的正整数。
        b: 密钥b，必须为整数。

    返回:
        加密后的密文字符串（全部小写）。

    异常:
        TypeError: 当参数类型不正确时抛出。
        ValueError: 当密钥无效或明文不包含字母时抛出。
    """
    _validate_text(plaintext, "明文")
    _validate_keys(a, b)

    ciphertext = ''
    for ch in plaintext:
        if ch.isalpha():
            x = ord(ch.lower()) - ord('a')
            y = (a * x + b) % 26
            ciphertext += chr(y + ord('a'))
        else:
            ciphertext += ch
    return ciphertext

def affine_decrypt(ciphertext, a, b):
    """仿射解密函数

    参数:
        ciphertext: 待解密的密文字符串，必须包含至少一个英文字母。
                    非字母字符将保持不变。
        a: 密钥a，必须为与26互质的正整数。
        b: 密钥b，必须为整数。

    返回:
        解密后的明文字符串（全部小写）。

    异常:
        TypeError: 当参数类型不正确时抛出。
        ValueError: 当密钥无效或密文不包含字母时抛出。
    """
    _validate_text(ciphertext, "密文")
    _validate_keys(a, b)

    # 求a的模26逆元
    a_inv = None
    for i in range(26):
        if (a * i) % 26 == 1:
            a_inv = i
            break

    plaintext = ''
    for ch in ciphertext:
        if ch.isalpha():
            y = ord(ch.lower()) - ord('a')
            x = (a_inv * (y - b)) % 26
            plaintext += chr(x + ord('a'))
        else:
            plaintext += ch
    return plaintext

def find_keys(known_plain, known_cipher):
    """通过已知明文-密文对找到可能的密钥(a,b)"""
    possible_keys = []
    
    # 将已知的明密文转换为数字
    plain_nums = [ord(ch.lower()) - ord('a') for ch in known_plain if ch.isalpha()]
    cipher_nums = [ord(ch.lower()) - ord('a') for ch in known_cipher if ch.isalpha()]
    
    if len(plain_nums) < 2 or len(cipher_nums) < 2:
        return possible_keys
    
    # 获取前两对明密文数字
    p1, p2 = plain_nums[0], plain_nums[1]
    c1, c2 = cipher_nums[0], cipher_nums[1]
    
    # 解方程组求解a和b
    # (a*p1 + b) ≡ c1 (mod 26)
    # (a*p2 + b) ≡ c2 (mod 26)
    
    # 两式相减：(a*(p1-p2)) ≡ (c1-c2) (mod 26)
    for a in range(1, 26):
        # 检查a是否与26互质
        if gcd(a, 26) != 1:
            continue
            
        # 检查a是否满足方程
        left = (a * (p1 - p2)) % 26
        right = (c1 - c2) % 26
        
        if left == right:
            # 计算b: b ≡ c1 - a*p1 (mod 26)
            b = (c1 - a * p1) % 26
            possible_keys.append((a, b))
    
    return possible_keys

def crack_affine_cipher(ciphertext, known_plain, known_cipher):
    """主函数：通过已知明密文对破解仿射密码"""
    # 1. 找到可能的密钥
    keys = find_keys(known_plain, known_cipher)
    
    if not keys:
        print("未找到有效密钥！请检查已知明密文对是否正确。")
        return []
    
    print(f"找到 {len(keys)} 个可能的密钥：")
    for i, (a, b) in enumerate(keys, 1):
        print(f"  密钥{i}: a={a}, b={b}")
    
    # 2. 用每个可能的密钥尝试解密
    results = []
    for a, b in keys:
        plaintext = affine_decrypt(ciphertext, a, b)
        if plaintext:
            results.append((a, b, plaintext))
            print(f"\n使用密钥 a={a}, b={b} 解密结果：")
            print(f"  {plaintext}")
    
    return results

# 示例：用题目的数据
if __name__ == "__main__":
    # 输入数据
    cipher = "edsgickxhuklzveqzvkxwkzukvcuh"
    known_plain = "if"  # 已知前两个明文字符
    known_cipher = "ed"  # 对应的密文字符
    
    print("密文:", cipher)
    print(f"已知: 明文 '{known_plain}' -> 密文 '{known_cipher}'")
    print("-" * 50)
    
    # 破解
    results = crack_affine_cipher(cipher, known_plain, known_cipher)
    
    # 验证：用找到的密钥加密已知明文，看是否得到已知密文
    if results:
        print("\n" + "=" * 50)
        print("验证结果：")
        for a, b, plain in results:
            encrypted = affine_encrypt(known_plain, a, b)
            is_correct = encrypted == known_cipher
            print(f"密钥(a={a},b={b}): 加密'{known_plain}' -> '{encrypted}'，与已知密文匹配: {is_correct}")
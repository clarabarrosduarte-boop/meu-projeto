def eh_palindromo(palavra):
    """Retorna True se 'palavra' for um palíndromo; False caso contrário.
    Ignora diferenças de maiúsculas/minúsculas e espaços nas pontas.
    """
    if not isinstance(palavra, str):
        raise TypeError("O parâmetro 'palavra' deve ser uma string.")
    s = palavra.strip().lower()
    return s == s[::-1]


if __name__ == "__main__":
    # Testes pedidos
    testes = ["radar", "python", "arara"]
    for t in testes:
        print(f"{t!r} -> {eh_palindromo(t)}")

    # Saída esperada:
    # 'radar' -> True
    # 'python' -> False
    # 'arara' -> True

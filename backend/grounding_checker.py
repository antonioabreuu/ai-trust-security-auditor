import re

def calculate_grounding_score(source: str, response: str) -> dict:
    """
    Compara a resposta gerada com a fonte fornecida para calcular o score de grounding.
    Retorna o score (0 a 1) e a classificação da fundamentação.
    """
    # Limpeza básica e tokenização para o MVP
    def tokenize(text):
        text = re.sub(r'[^\w\s]', '', text.lower())
        return set(text.split())

    source_words = tokenize(source)
    response_words = tokenize(response)

    if not response_words:
        return {"score": 0.0, "label": "inconclusivo"}

    # Ignorando palavras de parada comuns (stop words simples para o MVP)
    stop_words = {"o", "a", "os", "as", "um", "uma", "de", "do", "da", "em", "para", "com", "que", "é", "e", "sim", "nao", "não"}
    source_words = source_words - stop_words
    response_words = response_words - stop_words

    # Calcula quantas palavras cruciais da resposta estão na fonte
    overlap = source_words.intersection(response_words)
    
    # Se a resposta for muito curta, evitamos divisão por zero
    if len(response_words) == 0:
        score = 0.0
    else:
        score = len(overlap) / len(response_words)

    # Classificação baseada no score
    if score >= 0.5:
        label = "sustentada"
    elif score >= 0.2:
        label = "parcialmente sustentada"
    else:
        label = "sem suporte (possível alucinação)"

    return {
        "score": round(score, 2),
        "label": label
    }
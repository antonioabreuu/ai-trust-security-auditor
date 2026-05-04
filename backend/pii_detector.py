import re
from typing import List, Dict

# Expressões regulares para detecção dos padrões solicitados no MVP
PATTERNS = {
    "cpf": r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b",
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b",
    "telefone_br": r"\b(?:\+55\s?)?(?:\(?\d{2}\)?\s?)?\d{4,5}-?\d{4}\b",
    "aws_key": r"\bAKIA[0-9A-Z]{16}\b"
}

def mask_sensitive_data(text: str, pii_type: str) -> str:
    """Aplica o mascaramento obrigatório para evidências nos logs"""
    if pii_type == "cpf":
        return text[:4] + "***.***-**"
    elif pii_type == "email":
        parts = text.split("@")
        return parts[0][:2] + "***@" + parts[1]
    elif pii_type == "telefone_br":
        return text[:-4] + "****"
    elif pii_type == "aws_key":
        return "AKIA" + "*" * 16
    return "***MASCARADO***"

def scan_for_pii(text: str) -> List[Dict]:
    """Varre o texto em busca de padrões PII e retorna os achados"""
    findings = []
    
    for pii_type, pattern in PATTERNS.items():
        matches = re.finditer(pattern, text)
        for match in matches:
            found_text = match.group()
            findings.append({
                "type": pii_type,
                "evidence": mask_sensitive_data(found_text, pii_type)
            })
            
    return findings
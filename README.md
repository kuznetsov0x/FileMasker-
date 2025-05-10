# **FileMasker**

**Uma ferramenta de criptografia e camuflagem de arquivos** que converte arquivos comuns (como `.jpg`, `.txt`) em formatos disfarçados (como `.iso`, `.bin`) com criptografia **AES-256-GCM**, protegendo seus dados com senha forte.  

---

##  **Como Funciona?**  

1. **Criptografia Segura**:  
   - Usa **AES-256-GCM** (padrão militar) para criptografia autenticada.  
   - Deriva chaves usando **PBKDF2-HMAC-SHA256** (1.200.000 iterações).  
   - Protege contra adulteração com **tags de autenticação (GCM)**.  

2. **Camuflagem de Arquivos**:  
   - Transforma a extensão do arquivo (ex: `.jpg` → `.iso`) para disfarçar seu conteúdo.  
   - Mantém o nome original seguro dentro do arquivo criptografado.  

3. **Segurança Avançada**:  
   - Previne ataques de **timing** e **injeção de caminhos**.  
   - Apaga rastros com **exclusão segura** (3 passes de sobrescrita).  

---

## ⚙ **Como Usar?**  

### **1 Criptografar um Arquivo**  
```bash
python3 filemasker.py encrypt -i arquivo_secreto.txt -o saida.png
```
- Será solicitada uma senha (**mínimo 12 caracteres**).  
- O arquivo `saida.iso` conterá os dados criptografados.  

#### **Opções Adicionais**:  
| Argumento       | Descrição                                  |  
|-----------------|-------------------------------------------|  
| `-i/--input`    | Arquivo de entrada (obrigatório)          |  
| `-o/--output`   | Nome do arquivo de saída (padrão: `.enc`) |  
| `-p/--password` | Senha (evite usar no terminal!)           |  
| `--iterations`  | Iterações do PBKDF2 (padrão: 1.200.000)  |  

---

### **2 Descriptografar um Arquivo**  
```bash
python3 filemasker.py decrypt -i saida.iso -o pasta_de_saida/
```
- O arquivo original (com extensão real) será restaurado na pasta especificada.  

#### **Opções Adicionais**:  
| Argumento       | Descrição                                  |  
|-----------------|-------------------------------------------|  
| `-i/--input`    | Arquivo criptografado (obrigatório)       |  
| `-o/--output`   | Pasta/arquivo de saída (opcional)         |  

---

##  **Boas Práticas de Segurança**  
 **Use senhas fortes** (mínimo 12 caracteres, misture símbolos, números e letras).  
 **Prefira arquivos de senha** em vez de digitar no terminal:  
   ```bash
   python3 filemasker.py encrypt -i foto.jpg -p "$(cat senha.txt)"
   ```  
---

##  **Requisitos**  
- Python 3.8+  
- Bibliotecas: `cryptography`, `argparse`  

Instale as dependências com:  
```bash
pip install -r requirements.txt
```


---

# **FileMasker**  

**A file encryption and masking tool** that converts common files (like `.jpg`, `.txt`) into disguised formats (like `.iso`, `.bin`) with **AES-256-GCM encryption**, protecting your data with a strong password.  

---  

## **How It Works?**  

1. **Secure Encryption**:  
   - Uses **AES-256-GCM** (military-grade) for authenticated encryption.  
   - Derives keys using **PBKDF2-HMAC-SHA256** (1,200,000 iterations).  
   - Protects against tampering with **authentication tags (GCM)**.  

2. **File Masking**:  
   - Changes the file extension (e.g., `.jpg` → `.iso`) to hide its content.  
   - Keeps the original filename secure inside the encrypted file.  

3. **Advanced Security**:  
   - Prevents **timing attacks** and **path injection**.  
   - Erases traces with **secure deletion** (3-pass overwrite).  

---  

## ⚙ **How to Use?**  

### **1. Encrypt a File**  
```bash  
python3 filemasker.py encrypt -i secret_file.txt -o output.png  
```  
- You will be prompted for a password (**minimum 12 characters**).  
- The file `output.iso` will contain the encrypted data.  

#### **Additional Options**:  
| Argument       | Description                                  |  
|----------------|---------------------------------------------|  
| `-i/--input`   | Input file (required)                       |  
| `-o/--output`  | Output filename (default: `.enc`)           |  
| `-p/--password`| Password (avoid typing in terminal!)        |  
| `--iterations` | PBKDF2 iterations (default: 1,200,000)      |  

---  

### **2. Decrypt a File**  
```bash  
python3 filemasker.py decrypt -i output.iso -o output_folder/  
```  
- The original file (with its real extension) will be restored in the specified folder.  

#### **Additional Options**:  
| Argument       | Description                                  |  
|----------------|---------------------------------------------|  
| `-i/--input`   | Encrypted file (required)                   |  
| `-o/--output`  | Output folder/file (optional)               |  

---  

## **Security Best Practices**  
- **Use strong passwords** (minimum 12 characters, mix symbols, numbers, and letters).  
- **Prefer password files** instead of typing in the terminal:  
  ```bash  
  python3 filemasker.py encrypt -i photo.jpg -p "$(cat password.txt)"  
  ```  

---  

## **Requirements**  
- Python 3.8+  
- Libraries: `cryptography`, `argparse`  

Install dependencies with:  
```bash  
pip install -r requirements.txt  
```  

---  

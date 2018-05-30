# EasyCrypto

## Function
Provides an easy interface to AES. This program will encrypt and decrypt
items created by itself, file or string.

## Modules
Class EasyCrypto(object)
  def encrypt(string)
  def decrypt(string)

## Commandline Flags
-h, --help            show this help message and exit
-i DATA, --input=DATA
                      [REQUIRED] Data to be encrypted / decrypted
-e, --encrypt         Flag for encryption
-d, --decrypt         Flag for decryption
-f, --file            Flag for file decrypt / encrypt
-o, --outFile         File for output

## Example
__HELP__ </br>
EasyCrypto.py -h </br>
__Encrypt__ </br>
EasyCrypto.py -i "This Will De Encrypt, Printed to screen" -e                   </br>
EasyCrypto.py -i "This Will De Encrypt, Outputted to file" -e -o .//test         </br>
EasyCrypto.py -i "This Will De Encrypt a file, Outputted to file" -e -f -o .//test </br>
__Decrypt__ </br>
EasyCrypto.py -i "This Will De Decrypt, Printed to screen" -d                   </br>
EasyCrypto.py -i "This Will De Decrypt, Outputted to file" -d -o .//test         </br>
EasyCrypto.py -i "This Will De Decrypt a file, Outputted to file" -d -f -o .//test </br>

## Updates
30-05-2018 : Added pkcs2 module to help with C# decryption

## License
MIT copyright

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

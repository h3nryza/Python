# Quick_Crypto

Provides a quick way to either check a hash or encrypt / decrypt an item.
It facilitates reading either from an input file or just straight from cmd.

## Modules
Class hasher(object)
  def md(input):
  def sha256(input):
  def sha512(input):
Class crypto
  def encrypt_aes(input, key):
  def decrypt_aes(input, key):

## Commandline Flags
'-i', '--input', help='Input for hash, if any'
'-f', '--file', help='Flag Option if input is a file'
'-ha', '--hash', help='Flag for Hash Output'
'-ae', '--aes_encryption', help='Flag for AES Encryption'
'-ad', '--aes_decryption', help='Flag for AES Decryption'
'-ak', '--aes_key', dest='aes_key', help='Key for AES Encyption.Length of atleast 16'

## Examples
__HELP__ </br>
quick_crypt.py -h </br>
__Check hash of string__ </br>
quick_crypt .py -i 'What is the hash for this' -ha </br>
__Check hash of file__ </br>
quick_crypt.py  -i 'c://filetocheckhash.txt' -ha </br>
__Encrypt a String__ </br>
quick_crypt.py  -i 'I want to encrypt this' -ae -ak 'This key needs to be more than 16 characters'
__Decrypt a File__ </br>
quick_crypt.py  -i 'c:/inputfile.txt' -ae -ak 'This key needs to be more than 16 characters'


## License
MIT copyright

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

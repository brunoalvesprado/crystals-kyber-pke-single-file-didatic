
// #region Debug Level

enum DebugLevel {
    NONE = 0,
    ERROR = 1,
    WARN = 2,
    INFO = 3,
    DEBUG = 4,
    TRACE = 5,
}

class Logger {
    private level: DebugLevel;

    constructor(level: DebugLevel = DebugLevel.INFO) {
        this.level = level;
    }

    setLevel(level: DebugLevel): void {
        this.level = level;
    }

    error(...args: any[]): void {
        if (this.level >= DebugLevel.ERROR) {
            console.error(`[ERROR]:`, ...args);
        }
    }

    warn(...args: any[]): void {
        if (this.level >= DebugLevel.WARN) {
            console.warn(`[WARN]:`, ...args);
        }
    }

    info(...args: any[]): void {
        if (this.level >= DebugLevel.INFO) {
            console.info(`[INFO]:`, ...args);
        }
    }

    debug(...args: any[]): void {
        if (this.level >= DebugLevel.DEBUG) {
            console.debug(`[DEBUG]:`, ...args);
        }
    }

    trace(...args: any[]): void {
        if (this.level >= DebugLevel.TRACE) {
            console.trace(`[TRACE]:`, ...args);
        }
    }
}

// #endregion Debug Level

// #region Defined Types

type Polynomial = { coefficients: number[] };
type PolynomialMatrix = Polynomial[][];
type EncryptedBlock = {u:PolynomialMatrix, v:PolynomialMatrix};

type CrystalsKyberPublicKey = {t:PolynomialMatrix, A:PolynomialMatrix};
type CrystalsKyberPrivateKey = {s:PolynomialMatrix};
type CrystalsKyberKeys = {pKey:CrystalsKyberPublicKey, sKey:CrystalsKyberPrivateKey};

// #endregion Defined Types

// #region Math Operations

/**
 * Reduces the coefficient to it's binary value according to the distance between the maximum and minimum value.
 * @param {number} value - The absolute value of the input must be between the min and max range.
 * @param {number} minValue - Minimum value, unsigned.
 * @param {number} maxValue - Maximum value, unsigned.
 * @returns {number} - Result of the reduction.
 */
function reduceToBinary(value: number, minValue:number, maxValue:number): number {
    return Math.abs(value) > (Math.floor(maxValue / 2)) ? 1 : 0;
}

/**
 * Calculates the symmetric modulo Q value of a number.
 * @param {number} asymmetricValueModuloQ - Asymmetric value.
 * @param {number} moduloQ - Q modulo.
 * @returns {number} - Symmetric value modulo Q.
 */
function symmetricValueModuloQ(asymmetricValueModuloQ: number, moduloQ: number): number {
    let r = asymmetricValueModuloQ % moduloQ;
    let result:number;

    if(r < 0) {
        result= (r < - Math.floor(moduloQ / 2)) ? r + moduloQ : r;
    }
    else {
        result= (r > Math.floor(moduloQ / 2)) ? r - moduloQ : r;
    }

    return result;
}

// #endregion Math Operations

// #region Polynomial Operations

/**
 * Divides two polynomials and returns the remainder of the division.
 * @param {Polynomial} dividend - Dividend polynomial.
 * @param {Polynomial} dividingPolynomial - Dividing polynomial.
 * @param {number} moduloQ - Q modulo for the coefficients.
 * @returns {Polynomial} - Rest of the division.
 */
function dividePolynomials(dividend: Polynomial, dividingPolynomial: Polynomial, moduloQ: number): Polynomial {
    const dividendCoefficients = [...dividend.coefficients];
    const divisorDegree = dividingPolynomial.coefficients.length - 1;
    const divisorLeadingCoeff = dividingPolynomial.coefficients[divisorDegree];

    while (dividendCoefficients.length >= dividingPolynomial.coefficients.length) {
        const degreeDiff = dividendCoefficients.length - dividingPolynomial.coefficients.length;
        const leadingCoeff = Math.floor(dividendCoefficients[dividendCoefficients.length - 1] / divisorLeadingCoeff);

        for (let i = 0; i < dividingPolynomial.coefficients.length; i++) {
            dividendCoefficients[degreeDiff + i] -= symmetricValueModuloQ(dividingPolynomial.coefficients[i] * leadingCoeff, moduloQ);
            dividendCoefficients[degreeDiff + i] = symmetricValueModuloQ(dividendCoefficients[degreeDiff + i], moduloQ);
        }

        while (dividendCoefficients.length > 0 && dividendCoefficients[dividendCoefficients.length - 1] === 0) {
            dividendCoefficients.pop();
        }
    }

    return { coefficients: dividendCoefficients };
}

/**
 * Adds padding to polynomial blocks to ensure fixed size.
 * Adds byte 0x80 and fills the rest with zeros until the end whenever it is possible.
 * When the polynomial is the size of the block or larger, it does nothing.
 * @param {Polynomial} polynomial - Polynomial to be padded.
 * @param {number} blockSize - Block size.
 * @returns {Polynomial} - Padded polynomial.
 */
function addPaddingToPolynomialBlocks(polynomial: Polynomial, blockSize: number): Polynomial[] {
    const paddingByte = 0x80;

    const blocks: Polynomial[] = [];
    let currentBlock= polynomial.coefficients.slice();

    //Check if it's a already full block.
    if (currentBlock.length === blockSize) {
        blocks.push({ coefficients: currentBlock });
        currentBlock = [];
    }
    //Insert the padding byte.
    for (let bit = 7; bit >= 0; bit--) {
        currentBlock.push((paddingByte >> bit) & 1);
    }
    //If it got here full, it means there was only space for one byte, the padding byte, so we still need the zeros, therefore we create a new block.
    if (currentBlock.length === blockSize) {
        blocks.push({ coefficients: currentBlock });
        currentBlock = [];
    }

    //Fill with zeroes if necessary
    if (currentBlock.length < blockSize) {
        while (currentBlock.length < blockSize) {
            currentBlock.push(0);
        }   
    }

    blocks.push({ coefficients: currentBlock });

    return blocks;
}

/**
 * Remove padding from polynomial blocks.
 * @param {Polynomial} polynomial - Polynomial with padding.
 * @returns {Polynomial} - Polynomial without padding.
 */
function removePaddingFromPolynomialBlocks(polynomial: Polynomial): Polynomial {
    const coefficientsWithoutPadding = polynomial.coefficients.slice();

    while (coefficientsWithoutPadding.length > 0) {
        const last = coefficientsWithoutPadding[coefficientsWithoutPadding.length - 1];
        if (last === 0) {
            coefficientsWithoutPadding.pop();
        } else if (last === 1) {
            coefficientsWithoutPadding.pop();
            break;
        } else {
            break;
        }
    }

    return { coefficients: coefficientsWithoutPadding };
}

/**
 * Converts ASCII text into polynomial blocks with padding.
 * @param {string} text - Text to be converted.
 * @param {number} blockSize - Block size.
 * @returns {Polynomial[]} - Polynomial block with padding.
 */
function textToPolynomialBlocks(text: string, blockSize: number): Polynomial[] {
    var textBytes = Array.from(text).map(char => char.charCodeAt(0));  // Assumes ASCII text, meaning 8 bits per character.
    const blocks: Polynomial[] = [];
    let currentBlock: number[] = [];

    for (const byte of textBytes) {
        for (let bit = 7; bit >= 0; bit--) {
            if (currentBlock.length === blockSize) {
                blocks.push({ coefficients: currentBlock });                
                currentBlock = [];
            }

            currentBlock.push((byte >> bit) & 1);
        }
    }

    let paddedBlocks = addPaddingToPolynomialBlocks({ coefficients: currentBlock }, blockSize);

    for (let i = 0; i < paddedBlocks.length; i++) {
        blocks.push(paddedBlocks[i]);
    }

    return blocks;
}

/**
 * Converts the polynomial blocks to its original text.
 * @param {Polynomial[]} blocks - Polynomial blocks with padding.
 * @param {number} blockSize - Block size.
 * @returns {string} - Text rebuilt.
 */
function polynomialBlocksToText(blocks: Polynomial[], blockSize: number): string {
    let textBytes: number[] = [];

    for (const block of blocks) {
        let currentByte = 0;

        // For each block, loop through the coefficients (bits) and reconstruct the bytes.
        for (let i = 0; i < block.coefficients.length; i++) {
            currentByte = (currentByte << 1) | Number(block.coefficients[i]);
            
            // When the byte is complete, add it to the byte array.
            if ((i + 1) % 8 === 0) {
                textBytes.push(currentByte);
                currentByte = 0;
            }
        }
    }

    // Converts bytes back to characters and joins them to form the original text.
    let text = String.fromCharCode(...textBytes);

    return text;
}

// #endregion Polynomial Operations

// #region Matrix Operations

/**
 * Generates a matrix of random polynomials.
 * @param {number} rows - Number of rows in the matrix.
 * @param {number} cols - Number of columns in the matrix.
 * @param {number} n - Number of terms in the polynomial, ranging from degree 0 to n - 1.
 * @param {number} moduloQ - Q for specifying the ring of integers.
 * @returns {PolynomialMatrix} - Generated matrix.
 */
function generateRandomMatrix(rows: number, cols: number, n: number, moduloQ: number): PolynomialMatrix {
    const matrix: PolynomialMatrix = [];
    for (let i = 0; i < rows; i++) {
        const row: Polynomial[] = [];
        for (let j = 0; j < cols; j++) {
            const coefficients = Array.from({ length: n }, () => symmetricValueModuloQ(Math.floor(Math.random() * Number(moduloQ)), moduloQ));
            row.push({ coefficients });
        }
        matrix.push(row);
    }
    return matrix;
}

/**
 * Add two polynomial matrices.
 * @param {PolynomialMatrix} A - First matrix.
 * @param {PolynomialMatrix} B - Second matrix.
 * @param {number} moduloQ - Q modulo for the coefficients.
 * @param {Polynomial} modulusPolynomial - Polynomial modulus.
 * @returns {PolynomialMatrix} - Resulting matrix from the sum.
 */
function addMatrices(A: PolynomialMatrix, B: PolynomialMatrix, moduloQ: number, modulusPolynomial: Polynomial): PolynomialMatrix {
    if (A.length !== B.length || A[0].length !== B[0].length) {
        throw new Error("The dimensions of the matrices do not match.");
    }

    return A.map((row, i) => row.map((polyA, j) => {
        const polyB = B[i][j];
        const maxLength = Math.max(polyA.coefficients.length, polyB.coefficients.length);
        const coefficients = Array.from({ length: maxLength }, (_, k) => {
            const sum = (polyA.coefficients[k] || 0) + (polyB.coefficients[k] || 0);
            return symmetricValueModuloQ(sum, moduloQ);
        });
        const result = { coefficients };
        return dividePolynomials(result, modulusPolynomial, moduloQ);
    }));
}

/**
 * Subtracts two polynomial matrices.
 * @param {PolynomialMatrix} A - First matrix.
 * @param {PolynomialMatrix} B - Second matrix.
 * @param {number} moduloQ - Q modulo for the coefficients.
 * @param {Polynomial} modulusPolynomial - Polynomial modulus.
 * @returns {PolynomialMatrix} - Resulting matrix from the subtraction.
 */
function subtractMatrices(A: PolynomialMatrix, B: PolynomialMatrix, moduloQ: number, modulusPolynomial: Polynomial): PolynomialMatrix {
    if (A.length !== B.length || A[0].length !== B[0].length) {
        throw new Error("The dimensions of the matrices do not match.");
    }

    return A.map((row, i) => row.map((polyA, j) => {
        const polyB = B[i][j];
        const maxLength = Math.max(polyA.coefficients.length, polyB.coefficients.length);
        const coefficients = Array.from({ length: maxLength }, (_, k) => {
            const sum = (polyA.coefficients[k] || 0) - (polyB.coefficients[k] || 0);
            return symmetricValueModuloQ(sum, moduloQ);
        });
        const result = { coefficients };
        return dividePolynomials(result, modulusPolynomial, moduloQ);
    }));
}

/**
 * Multiplies two polynomial matrices.
 * @param {PolynomialMatrix} A - First matrix.
 * @param {PolynomialMatrix} B - Second matrix.
 * @param {number} moduloQ - Q modulo for the coefficients.
 * @param {Polynomial} modulusPolynomial - Polynomial modulus.
 * @returns {PolynomialMatrix} - Resulting matrix from the multiplication.
 */
function multiplyMatrices(A: PolynomialMatrix, B: PolynomialMatrix, moduloQ: number, modulusPolynomial: Polynomial): PolynomialMatrix {
    if (A[0].length !== B.length) {
        throw new Error("The number of columns in the first matrix must be equal to the number of rows in the second matrix.");
    }

    const result: PolynomialMatrix = Array.from({ length: A.length }, () => Array(B[0].length).fill(null).map(() => ({ coefficients: [] })));

    for (let i = 0; i < A.length; i++) {
        for (let j = 0; j < B[0].length; j++) {
            for (let k = 0; k < B.length; k++) {
                const polyA = A[i][k];
                const polyB = B[k][j];
                const productCoefficients = Array.from({ length: polyA.coefficients.length + polyB.coefficients.length - 1 }, () => 0);

                polyA.coefficients.forEach((coeffA, indexA) => {
                    polyB.coefficients.forEach((coeffB, indexB) => {
                        productCoefficients[indexA + indexB] += coeffA * coeffB;
                    });
                });

                const current = result[i][j];
                const maxLength = Math.max(current.coefficients.length, productCoefficients.length);
                const summedCoefficients = Array.from({ length: maxLength }, (_, k) => {
                    const sum = (current.coefficients[k] || 0) + (productCoefficients[k] || 0);
                    return symmetricValueModuloQ(sum, moduloQ);
                });

                result[i][j] = { coefficients: summedCoefficients };
            }
            result[i][j] = dividePolynomials(result[i][j], modulusPolynomial, moduloQ);
        }
    }

    return result;
}

/**
 * Returns the transposed matrix.
 * @param {PolynomialMatrix} matrix - Original matrix.
 * @returns {PolynomialMatrix} - Transposed matrix.
 */
function transposeMatrix(matrix: PolynomialMatrix): PolynomialMatrix {
    const rows = matrix.length;
    const cols = matrix[0].length;
    const transposed: PolynomialMatrix = Array.from({ length: cols }, () => []);

    for (let i = 0; i < rows; i++) {
        for (let j = 0; j < cols; j++) {
            transposed[j][i] = matrix[i][j];
        }
    }

    return transposed;
}

// #endregion Matrix Operations

// #region Crystals-Kyber Parameters

// //CRYSTALS-KYBER PARAMETERS Kyber512
// let q = 3329;
// let n = 256;
// let k = 2;
// let n1 = 3;
// let n2 = 2;

// //CRYSTALS-KYBER PARAMETERS Kyber768
// let q = 3329;
// let n = 256;
// let k = 3;
// let n1 = 2;
// let n2 = 2;

// //CRYSTALS-KYBER PARAMETERS Kyber1024
// let q = 3329;
// let n = 256;
// let k = 4;
// let n1 = 2;
// let n2 = 2;

//CRYSTALS-KYBER PARAMETERS Customized
let q = 3329;
let n = 256;
let k = 4;
let n1 = 2;
let n2 = 2;

const divisor = Array(n+1).fill(0); // n+1 because the polynomial needs to be one degree larger.
divisor[0] = 1;
divisor[n] = 1;
const modulusPolynomial={ coefficients: divisor }; // Polynomial with value 1 on terms of lowest degree and highest degree.

// #endregion Crystals-Kyber Parameters

// #region Cryptographic Functions

function crystalsKyber_generateKeys():CrystalsKyberKeys {
    const s = generateRandomMatrix(k, 1, n, (n1*2)+1); // uses modular arithmetic inside generateRandomMatrix() to ensure the range value of the coefficients on the range eta [ -n1, n1 ].
    const e = generateRandomMatrix(k, 1, n, (n2*2)+1);
    const A = generateRandomMatrix(k, k, n, q);

    logger.debug('s', s);
    logger.debug('e', e);
    logger.debug('A', A);
    const t = addMatrices(multiplyMatrices(A, s, q, modulusPolynomial), e, q, modulusPolynomial);
    logger.debug('t', t);

    return {pKey:{t, A}, sKey:{s}};
}

function crystalsKyber_encrypt(msg: Polynomial, pKey:CrystalsKyberPublicKey):EncryptedBlock  {
    const encrypt_r = generateRandomMatrix(k, 1, n, (n1*2)+1);
    const e1 = generateRandomMatrix(k, 1, n, (n2*2)+1);
    const e2 = generateRandomMatrix(1, 1, n, (n2*2)+1);

    logger.debug('e1', e1);
    logger.debug('e2', e2);

    const msgScaled:Polynomial = { coefficients: msg.coefficients.map(coeff => coeff * (q/2))};
    const matrixMsgScaled:PolynomialMatrix = Array.from({ length: 1 }, () => Array.from({ length: 1 }, () => (msgScaled)));

    logger.debug('msg', msg);
    logger.debug('msgScaled', msgScaled);

    //PAR DE VALORES QUE COMPÕEM A MENSAGEM CRIPTOGRAFADA
    const u = addMatrices(multiplyMatrices(transposeMatrix(pKey.A), encrypt_r, q, modulusPolynomial), e1, q, modulusPolynomial);
    const v = addMatrices(addMatrices(multiplyMatrices(transposeMatrix(pKey.t), encrypt_r, q, modulusPolynomial), e2, q, modulusPolynomial), matrixMsgScaled, q, modulusPolynomial);

    logger.debug('u', u);
    logger.debug('v', v);

    return {u, v};
}

function crystalsKyber_decrypt(eb:EncryptedBlock, sKey:CrystalsKyberPrivateKey):Polynomial {
    const msg_decrypted = subtractMatrices(eb.v, multiplyMatrices(transposeMatrix(sKey.s), eb.u, q, modulusPolynomial), q, modulusPolynomial);
    const msg_polynomial= msg_decrypted[0][0];

    logger.debug('msg_decrypted', msg_decrypted);
    logger.debug('msg_polynomial', msg_polynomial);

    const msgFullyDecrypted:Polynomial = { coefficients: msg_polynomial.coefficients.map(coeff => reduceToBinary(coeff, 0, q/2))};

    logger.debug('fully decrypted', msgFullyDecrypted);

    return msgFullyDecrypted;
}

function crystalsKyber_encryptMessage(message:string, pKey:CrystalsKyberPublicKey):EncryptedBlock[] {
    var polynomialsToEncrypt=textToPolynomialBlocks(message, n);
    logger.debug('polynomialsToEncrypt', polynomialsToEncrypt);
    
    var encryptedPolynomialBlocks:EncryptedBlock[]=[];
    
    for (let i = 0; i < polynomialsToEncrypt.length; i++) {
        let ct = crystalsKyber_encrypt(polynomialsToEncrypt[i], pKey);
        encryptedPolynomialBlocks .push(ct);
    }

    return encryptedPolynomialBlocks;
}

function crystalsKyber_decryptMessage(encryptedMsg:EncryptedBlock[], sKey:CrystalsKyberPrivateKey):string {
    var polynomialsDecrypted:Polynomial[]= [];
    var polynomialsDecryptedWithoutPadding:Polynomial[]= [];

    for (let i = 0; i < encryptedMsg.length; i++) {
        const pDecrypted = crystalsKyber_decrypt(encryptedMsg[i], sKey);
        polynomialsDecrypted.push(pDecrypted);
    }

    //Checks if the last block is filled with only zeros.
    let allZeroes=true;
    let lastPolynomialCoefficients=polynomialsDecrypted[polynomialsDecrypted.length-1].coefficients;
    for (let i = 0; i < lastPolynomialCoefficients.length; i++) {
        if(lastPolynomialCoefficients[i] != 0) {
            allZeroes=false;
            break;
        }
    }
    
    //Ensures removePaddingFromPolynomialBlocks() is applied to the appropriate block. In other words, if the block is filled only by zeroes the padding byte is in the previous block, and fully zeroed block can be discarded.
    if(allZeroes) {
        polynomialsDecrypted.pop();
    }

    for (let i = 0; i < polynomialsDecrypted.length; i++) {
        if(i === polynomialsDecrypted.length-1)
            polynomialsDecryptedWithoutPadding.push(removePaddingFromPolynomialBlocks(polynomialsDecrypted[i]));
        else
            polynomialsDecryptedWithoutPadding.push(polynomialsDecrypted[i]);
    } 

    let msg=polynomialBlocksToText(polynomialsDecryptedWithoutPadding, n);

    return msg;
}

// #endregion Cryptographic Functions

function separatorLine() {
    logger.info('------------------------------------------------------------------------------------------------------');
}
const logger = new Logger(DebugLevel.INFO);

// Generate Alice and Bob keys.
let {pKey:Alice_pKey, sKey:Alice_sKey} = crystalsKyber_generateKeys();
let {pKey:Bob_pKey, sKey:Bob_sKey} = crystalsKyber_generateKeys();

separatorLine();

// Alice -> Bob
let msgAlice = "Hey Bob, Alice here, how are you?";

logger.info('Alice writes:', msgAlice);
let ctMsgAlice = crystalsKyber_encryptMessage(msgAlice, Bob_pKey);
logger.info('Eve reads:', ctMsgAlice);
let decryptedMsgAlice = crystalsKyber_decryptMessage(ctMsgAlice, Bob_sKey);
logger.info('Bob reads:', decryptedMsgAlice);
logger.info('MATCH:', decryptedMsgAlice === msgAlice);

separatorLine();

// Bob -> Alice
let msgBob = "Yes Alice, this is Bob, I'm fine, how are you too?";

logger.info('Bob writes:', msgBob);
let ctMsgBob = crystalsKyber_encryptMessage(msgBob, Alice_pKey);
logger.info('Eve reads:', ctMsgBob);
let decryptedMsgBob = crystalsKyber_decryptMessage(ctMsgBob, Alice_sKey);
logger.info('Alice reads:', decryptedMsgBob);
logger.info('MATCH:', decryptedMsgBob === msgBob);

separatorLine();

logger.info('End');

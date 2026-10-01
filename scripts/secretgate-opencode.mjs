#!/usr/bin/env node

// src/adapters/opencode-plugin.ts
import { fileURLToPath } from "url";

// src/config.ts
import { createHash as createHash2 } from "crypto";
import { existsSync, mkdirSync as mkdirSync2, readFileSync as readFileSync2, renameSync as renameSync2, writeFileSync } from "fs";
import { homedir as homedir3 } from "os";
import { dirname as dirname3, join as join4, resolve as resolve3 } from "path";

// node_modules/.pnpm/jsonc-parser@3.3.1/node_modules/jsonc-parser/lib/esm/impl/scanner.js
function createScanner(text, ignoreTrivia = false) {
  const len = text.length;
  let pos = 0, value = "", tokenOffset = 0, token = 16, lineNumber = 0, lineStartOffset = 0, tokenLineStartOffset = 0, prevTokenLineStartOffset = 0, scanError = 0;
  function scanHexDigits(count, exact) {
    let digits = 0;
    let value2 = 0;
    while (digits < count || !exact) {
      let ch = text.charCodeAt(pos);
      if (ch >= 48 && ch <= 57) {
        value2 = value2 * 16 + ch - 48;
      } else if (ch >= 65 && ch <= 70) {
        value2 = value2 * 16 + ch - 65 + 10;
      } else if (ch >= 97 && ch <= 102) {
        value2 = value2 * 16 + ch - 97 + 10;
      } else {
        break;
      }
      pos++;
      digits++;
    }
    if (digits < count) {
      value2 = -1;
    }
    return value2;
  }
  function setPosition(newPosition) {
    pos = newPosition;
    value = "";
    tokenOffset = 0;
    token = 16;
    scanError = 0;
  }
  function scanNumber() {
    let start = pos;
    if (text.charCodeAt(pos) === 48) {
      pos++;
    } else {
      pos++;
      while (pos < text.length && isDigit(text.charCodeAt(pos))) {
        pos++;
      }
    }
    if (pos < text.length && text.charCodeAt(pos) === 46) {
      pos++;
      if (pos < text.length && isDigit(text.charCodeAt(pos))) {
        pos++;
        while (pos < text.length && isDigit(text.charCodeAt(pos))) {
          pos++;
        }
      } else {
        scanError = 3;
        return text.substring(start, pos);
      }
    }
    let end = pos;
    if (pos < text.length && (text.charCodeAt(pos) === 69 || text.charCodeAt(pos) === 101)) {
      pos++;
      if (pos < text.length && text.charCodeAt(pos) === 43 || text.charCodeAt(pos) === 45) {
        pos++;
      }
      if (pos < text.length && isDigit(text.charCodeAt(pos))) {
        pos++;
        while (pos < text.length && isDigit(text.charCodeAt(pos))) {
          pos++;
        }
        end = pos;
      } else {
        scanError = 3;
      }
    }
    return text.substring(start, end);
  }
  function scanString() {
    let result = "", start = pos;
    while (true) {
      if (pos >= len) {
        result += text.substring(start, pos);
        scanError = 2;
        break;
      }
      const ch = text.charCodeAt(pos);
      if (ch === 34) {
        result += text.substring(start, pos);
        pos++;
        break;
      }
      if (ch === 92) {
        result += text.substring(start, pos);
        pos++;
        if (pos >= len) {
          scanError = 2;
          break;
        }
        const ch2 = text.charCodeAt(pos++);
        switch (ch2) {
          case 34:
            result += '"';
            break;
          case 92:
            result += "\\";
            break;
          case 47:
            result += "/";
            break;
          case 98:
            result += "\b";
            break;
          case 102:
            result += "\f";
            break;
          case 110:
            result += "\n";
            break;
          case 114:
            result += "\r";
            break;
          case 116:
            result += "	";
            break;
          case 117:
            const ch3 = scanHexDigits(4, true);
            if (ch3 >= 0) {
              result += String.fromCharCode(ch3);
            } else {
              scanError = 4;
            }
            break;
          default:
            scanError = 5;
        }
        start = pos;
        continue;
      }
      if (ch >= 0 && ch <= 31) {
        if (isLineBreak(ch)) {
          result += text.substring(start, pos);
          scanError = 2;
          break;
        } else {
          scanError = 6;
        }
      }
      pos++;
    }
    return result;
  }
  function scanNext() {
    value = "";
    scanError = 0;
    tokenOffset = pos;
    lineStartOffset = lineNumber;
    prevTokenLineStartOffset = tokenLineStartOffset;
    if (pos >= len) {
      tokenOffset = len;
      return token = 17;
    }
    let code = text.charCodeAt(pos);
    if (isWhiteSpace(code)) {
      do {
        pos++;
        value += String.fromCharCode(code);
        code = text.charCodeAt(pos);
      } while (isWhiteSpace(code));
      return token = 15;
    }
    if (isLineBreak(code)) {
      pos++;
      value += String.fromCharCode(code);
      if (code === 13 && text.charCodeAt(pos) === 10) {
        pos++;
        value += "\n";
      }
      lineNumber++;
      tokenLineStartOffset = pos;
      return token = 14;
    }
    switch (code) {
      // tokens: []{}:,
      case 123:
        pos++;
        return token = 1;
      case 125:
        pos++;
        return token = 2;
      case 91:
        pos++;
        return token = 3;
      case 93:
        pos++;
        return token = 4;
      case 58:
        pos++;
        return token = 6;
      case 44:
        pos++;
        return token = 5;
      // strings
      case 34:
        pos++;
        value = scanString();
        return token = 10;
      // comments
      case 47:
        const start = pos - 1;
        if (text.charCodeAt(pos + 1) === 47) {
          pos += 2;
          while (pos < len) {
            if (isLineBreak(text.charCodeAt(pos))) {
              break;
            }
            pos++;
          }
          value = text.substring(start, pos);
          return token = 12;
        }
        if (text.charCodeAt(pos + 1) === 42) {
          pos += 2;
          const safeLength = len - 1;
          let commentClosed = false;
          while (pos < safeLength) {
            const ch = text.charCodeAt(pos);
            if (ch === 42 && text.charCodeAt(pos + 1) === 47) {
              pos += 2;
              commentClosed = true;
              break;
            }
            pos++;
            if (isLineBreak(ch)) {
              if (ch === 13 && text.charCodeAt(pos) === 10) {
                pos++;
              }
              lineNumber++;
              tokenLineStartOffset = pos;
            }
          }
          if (!commentClosed) {
            pos++;
            scanError = 1;
          }
          value = text.substring(start, pos);
          return token = 13;
        }
        value += String.fromCharCode(code);
        pos++;
        return token = 16;
      // numbers
      case 45:
        value += String.fromCharCode(code);
        pos++;
        if (pos === len || !isDigit(text.charCodeAt(pos))) {
          return token = 16;
        }
      // found a minus, followed by a number so
      // we fall through to proceed with scanning
      // numbers
      case 48:
      case 49:
      case 50:
      case 51:
      case 52:
      case 53:
      case 54:
      case 55:
      case 56:
      case 57:
        value += scanNumber();
        return token = 11;
      // literals and unknown symbols
      default:
        while (pos < len && isUnknownContentCharacter(code)) {
          pos++;
          code = text.charCodeAt(pos);
        }
        if (tokenOffset !== pos) {
          value = text.substring(tokenOffset, pos);
          switch (value) {
            case "true":
              return token = 8;
            case "false":
              return token = 9;
            case "null":
              return token = 7;
          }
          return token = 16;
        }
        value += String.fromCharCode(code);
        pos++;
        return token = 16;
    }
  }
  function isUnknownContentCharacter(code) {
    if (isWhiteSpace(code) || isLineBreak(code)) {
      return false;
    }
    switch (code) {
      case 125:
      case 93:
      case 123:
      case 91:
      case 34:
      case 58:
      case 44:
      case 47:
        return false;
    }
    return true;
  }
  function scanNextNonTrivia() {
    let result;
    do {
      result = scanNext();
    } while (result >= 12 && result <= 15);
    return result;
  }
  return {
    setPosition,
    getPosition: () => pos,
    scan: ignoreTrivia ? scanNextNonTrivia : scanNext,
    getToken: () => token,
    getTokenValue: () => value,
    getTokenOffset: () => tokenOffset,
    getTokenLength: () => pos - tokenOffset,
    getTokenStartLine: () => lineStartOffset,
    getTokenStartCharacter: () => tokenOffset - prevTokenLineStartOffset,
    getTokenError: () => scanError
  };
}
function isWhiteSpace(ch) {
  return ch === 32 || ch === 9;
}
function isLineBreak(ch) {
  return ch === 10 || ch === 13;
}
function isDigit(ch) {
  return ch >= 48 && ch <= 57;
}
var CharacterCodes;
(function(CharacterCodes2) {
  CharacterCodes2[CharacterCodes2["lineFeed"] = 10] = "lineFeed";
  CharacterCodes2[CharacterCodes2["carriageReturn"] = 13] = "carriageReturn";
  CharacterCodes2[CharacterCodes2["space"] = 32] = "space";
  CharacterCodes2[CharacterCodes2["_0"] = 48] = "_0";
  CharacterCodes2[CharacterCodes2["_1"] = 49] = "_1";
  CharacterCodes2[CharacterCodes2["_2"] = 50] = "_2";
  CharacterCodes2[CharacterCodes2["_3"] = 51] = "_3";
  CharacterCodes2[CharacterCodes2["_4"] = 52] = "_4";
  CharacterCodes2[CharacterCodes2["_5"] = 53] = "_5";
  CharacterCodes2[CharacterCodes2["_6"] = 54] = "_6";
  CharacterCodes2[CharacterCodes2["_7"] = 55] = "_7";
  CharacterCodes2[CharacterCodes2["_8"] = 56] = "_8";
  CharacterCodes2[CharacterCodes2["_9"] = 57] = "_9";
  CharacterCodes2[CharacterCodes2["a"] = 97] = "a";
  CharacterCodes2[CharacterCodes2["b"] = 98] = "b";
  CharacterCodes2[CharacterCodes2["c"] = 99] = "c";
  CharacterCodes2[CharacterCodes2["d"] = 100] = "d";
  CharacterCodes2[CharacterCodes2["e"] = 101] = "e";
  CharacterCodes2[CharacterCodes2["f"] = 102] = "f";
  CharacterCodes2[CharacterCodes2["g"] = 103] = "g";
  CharacterCodes2[CharacterCodes2["h"] = 104] = "h";
  CharacterCodes2[CharacterCodes2["i"] = 105] = "i";
  CharacterCodes2[CharacterCodes2["j"] = 106] = "j";
  CharacterCodes2[CharacterCodes2["k"] = 107] = "k";
  CharacterCodes2[CharacterCodes2["l"] = 108] = "l";
  CharacterCodes2[CharacterCodes2["m"] = 109] = "m";
  CharacterCodes2[CharacterCodes2["n"] = 110] = "n";
  CharacterCodes2[CharacterCodes2["o"] = 111] = "o";
  CharacterCodes2[CharacterCodes2["p"] = 112] = "p";
  CharacterCodes2[CharacterCodes2["q"] = 113] = "q";
  CharacterCodes2[CharacterCodes2["r"] = 114] = "r";
  CharacterCodes2[CharacterCodes2["s"] = 115] = "s";
  CharacterCodes2[CharacterCodes2["t"] = 116] = "t";
  CharacterCodes2[CharacterCodes2["u"] = 117] = "u";
  CharacterCodes2[CharacterCodes2["v"] = 118] = "v";
  CharacterCodes2[CharacterCodes2["w"] = 119] = "w";
  CharacterCodes2[CharacterCodes2["x"] = 120] = "x";
  CharacterCodes2[CharacterCodes2["y"] = 121] = "y";
  CharacterCodes2[CharacterCodes2["z"] = 122] = "z";
  CharacterCodes2[CharacterCodes2["A"] = 65] = "A";
  CharacterCodes2[CharacterCodes2["B"] = 66] = "B";
  CharacterCodes2[CharacterCodes2["C"] = 67] = "C";
  CharacterCodes2[CharacterCodes2["D"] = 68] = "D";
  CharacterCodes2[CharacterCodes2["E"] = 69] = "E";
  CharacterCodes2[CharacterCodes2["F"] = 70] = "F";
  CharacterCodes2[CharacterCodes2["G"] = 71] = "G";
  CharacterCodes2[CharacterCodes2["H"] = 72] = "H";
  CharacterCodes2[CharacterCodes2["I"] = 73] = "I";
  CharacterCodes2[CharacterCodes2["J"] = 74] = "J";
  CharacterCodes2[CharacterCodes2["K"] = 75] = "K";
  CharacterCodes2[CharacterCodes2["L"] = 76] = "L";
  CharacterCodes2[CharacterCodes2["M"] = 77] = "M";
  CharacterCodes2[CharacterCodes2["N"] = 78] = "N";
  CharacterCodes2[CharacterCodes2["O"] = 79] = "O";
  CharacterCodes2[CharacterCodes2["P"] = 80] = "P";
  CharacterCodes2[CharacterCodes2["Q"] = 81] = "Q";
  CharacterCodes2[CharacterCodes2["R"] = 82] = "R";
  CharacterCodes2[CharacterCodes2["S"] = 83] = "S";
  CharacterCodes2[CharacterCodes2["T"] = 84] = "T";
  CharacterCodes2[CharacterCodes2["U"] = 85] = "U";
  CharacterCodes2[CharacterCodes2["V"] = 86] = "V";
  CharacterCodes2[CharacterCodes2["W"] = 87] = "W";
  CharacterCodes2[CharacterCodes2["X"] = 88] = "X";
  CharacterCodes2[CharacterCodes2["Y"] = 89] = "Y";
  CharacterCodes2[CharacterCodes2["Z"] = 90] = "Z";
  CharacterCodes2[CharacterCodes2["asterisk"] = 42] = "asterisk";
  CharacterCodes2[CharacterCodes2["backslash"] = 92] = "backslash";
  CharacterCodes2[CharacterCodes2["closeBrace"] = 125] = "closeBrace";
  CharacterCodes2[CharacterCodes2["closeBracket"] = 93] = "closeBracket";
  CharacterCodes2[CharacterCodes2["colon"] = 58] = "colon";
  CharacterCodes2[CharacterCodes2["comma"] = 44] = "comma";
  CharacterCodes2[CharacterCodes2["dot"] = 46] = "dot";
  CharacterCodes2[CharacterCodes2["doubleQuote"] = 34] = "doubleQuote";
  CharacterCodes2[CharacterCodes2["minus"] = 45] = "minus";
  CharacterCodes2[CharacterCodes2["openBrace"] = 123] = "openBrace";
  CharacterCodes2[CharacterCodes2["openBracket"] = 91] = "openBracket";
  CharacterCodes2[CharacterCodes2["plus"] = 43] = "plus";
  CharacterCodes2[CharacterCodes2["slash"] = 47] = "slash";
  CharacterCodes2[CharacterCodes2["formFeed"] = 12] = "formFeed";
  CharacterCodes2[CharacterCodes2["tab"] = 9] = "tab";
})(CharacterCodes || (CharacterCodes = {}));

// node_modules/.pnpm/jsonc-parser@3.3.1/node_modules/jsonc-parser/lib/esm/impl/string-intern.js
var cachedSpaces = new Array(20).fill(0).map((_, index) => {
  return " ".repeat(index);
});
var maxCachedValues = 200;
var cachedBreakLinesWithSpaces = {
  " ": {
    "\n": new Array(maxCachedValues).fill(0).map((_, index) => {
      return "\n" + " ".repeat(index);
    }),
    "\r": new Array(maxCachedValues).fill(0).map((_, index) => {
      return "\r" + " ".repeat(index);
    }),
    "\r\n": new Array(maxCachedValues).fill(0).map((_, index) => {
      return "\r\n" + " ".repeat(index);
    })
  },
  "	": {
    "\n": new Array(maxCachedValues).fill(0).map((_, index) => {
      return "\n" + "	".repeat(index);
    }),
    "\r": new Array(maxCachedValues).fill(0).map((_, index) => {
      return "\r" + "	".repeat(index);
    }),
    "\r\n": new Array(maxCachedValues).fill(0).map((_, index) => {
      return "\r\n" + "	".repeat(index);
    })
  }
};

// node_modules/.pnpm/jsonc-parser@3.3.1/node_modules/jsonc-parser/lib/esm/impl/parser.js
var ParseOptions;
(function(ParseOptions2) {
  ParseOptions2.DEFAULT = {
    allowTrailingComma: false
  };
})(ParseOptions || (ParseOptions = {}));
function parse(text, errors = [], options = ParseOptions.DEFAULT) {
  let currentProperty = null;
  let currentParent = [];
  const previousParents = [];
  function onValue(value) {
    if (Array.isArray(currentParent)) {
      currentParent.push(value);
    } else if (currentProperty !== null) {
      currentParent[currentProperty] = value;
    }
  }
  const visitor = {
    onObjectBegin: () => {
      const object = {};
      onValue(object);
      previousParents.push(currentParent);
      currentParent = object;
      currentProperty = null;
    },
    onObjectProperty: (name) => {
      currentProperty = name;
    },
    onObjectEnd: () => {
      currentParent = previousParents.pop();
    },
    onArrayBegin: () => {
      const array = [];
      onValue(array);
      previousParents.push(currentParent);
      currentParent = array;
      currentProperty = null;
    },
    onArrayEnd: () => {
      currentParent = previousParents.pop();
    },
    onLiteralValue: onValue,
    onError: (error, offset, length) => {
      errors.push({ error, offset, length });
    }
  };
  visit(text, visitor, options);
  return currentParent[0];
}
function visit(text, visitor, options = ParseOptions.DEFAULT) {
  const _scanner = createScanner(text, false);
  const _jsonPath = [];
  let suppressedCallbacks = 0;
  function toNoArgVisit(visitFunction) {
    return visitFunction ? () => suppressedCallbacks === 0 && visitFunction(_scanner.getTokenOffset(), _scanner.getTokenLength(), _scanner.getTokenStartLine(), _scanner.getTokenStartCharacter()) : () => true;
  }
  function toOneArgVisit(visitFunction) {
    return visitFunction ? (arg) => suppressedCallbacks === 0 && visitFunction(arg, _scanner.getTokenOffset(), _scanner.getTokenLength(), _scanner.getTokenStartLine(), _scanner.getTokenStartCharacter()) : () => true;
  }
  function toOneArgVisitWithPath(visitFunction) {
    return visitFunction ? (arg) => suppressedCallbacks === 0 && visitFunction(arg, _scanner.getTokenOffset(), _scanner.getTokenLength(), _scanner.getTokenStartLine(), _scanner.getTokenStartCharacter(), () => _jsonPath.slice()) : () => true;
  }
  function toBeginVisit(visitFunction) {
    return visitFunction ? () => {
      if (suppressedCallbacks > 0) {
        suppressedCallbacks++;
      } else {
        let cbReturn = visitFunction(_scanner.getTokenOffset(), _scanner.getTokenLength(), _scanner.getTokenStartLine(), _scanner.getTokenStartCharacter(), () => _jsonPath.slice());
        if (cbReturn === false) {
          suppressedCallbacks = 1;
        }
      }
    } : () => true;
  }
  function toEndVisit(visitFunction) {
    return visitFunction ? () => {
      if (suppressedCallbacks > 0) {
        suppressedCallbacks--;
      }
      if (suppressedCallbacks === 0) {
        visitFunction(_scanner.getTokenOffset(), _scanner.getTokenLength(), _scanner.getTokenStartLine(), _scanner.getTokenStartCharacter());
      }
    } : () => true;
  }
  const onObjectBegin = toBeginVisit(visitor.onObjectBegin), onObjectProperty = toOneArgVisitWithPath(visitor.onObjectProperty), onObjectEnd = toEndVisit(visitor.onObjectEnd), onArrayBegin = toBeginVisit(visitor.onArrayBegin), onArrayEnd = toEndVisit(visitor.onArrayEnd), onLiteralValue = toOneArgVisitWithPath(visitor.onLiteralValue), onSeparator = toOneArgVisit(visitor.onSeparator), onComment = toNoArgVisit(visitor.onComment), onError = toOneArgVisit(visitor.onError);
  const disallowComments = options && options.disallowComments;
  const allowTrailingComma = options && options.allowTrailingComma;
  function scanNext() {
    while (true) {
      const token = _scanner.scan();
      switch (_scanner.getTokenError()) {
        case 4:
          handleError(
            14
            /* ParseErrorCode.InvalidUnicode */
          );
          break;
        case 5:
          handleError(
            15
            /* ParseErrorCode.InvalidEscapeCharacter */
          );
          break;
        case 3:
          handleError(
            13
            /* ParseErrorCode.UnexpectedEndOfNumber */
          );
          break;
        case 1:
          if (!disallowComments) {
            handleError(
              11
              /* ParseErrorCode.UnexpectedEndOfComment */
            );
          }
          break;
        case 2:
          handleError(
            12
            /* ParseErrorCode.UnexpectedEndOfString */
          );
          break;
        case 6:
          handleError(
            16
            /* ParseErrorCode.InvalidCharacter */
          );
          break;
      }
      switch (token) {
        case 12:
        case 13:
          if (disallowComments) {
            handleError(
              10
              /* ParseErrorCode.InvalidCommentToken */
            );
          } else {
            onComment();
          }
          break;
        case 16:
          handleError(
            1
            /* ParseErrorCode.InvalidSymbol */
          );
          break;
        case 15:
        case 14:
          break;
        default:
          return token;
      }
    }
  }
  function handleError(error, skipUntilAfter = [], skipUntil = []) {
    onError(error);
    if (skipUntilAfter.length + skipUntil.length > 0) {
      let token = _scanner.getToken();
      while (token !== 17) {
        if (skipUntilAfter.indexOf(token) !== -1) {
          scanNext();
          break;
        } else if (skipUntil.indexOf(token) !== -1) {
          break;
        }
        token = scanNext();
      }
    }
  }
  function parseString(isValue) {
    const value = _scanner.getTokenValue();
    if (isValue) {
      onLiteralValue(value);
    } else {
      onObjectProperty(value);
      _jsonPath.push(value);
    }
    scanNext();
    return true;
  }
  function parseLiteral() {
    switch (_scanner.getToken()) {
      case 11:
        const tokenValue = _scanner.getTokenValue();
        let value = Number(tokenValue);
        if (isNaN(value)) {
          handleError(
            2
            /* ParseErrorCode.InvalidNumberFormat */
          );
          value = 0;
        }
        onLiteralValue(value);
        break;
      case 7:
        onLiteralValue(null);
        break;
      case 8:
        onLiteralValue(true);
        break;
      case 9:
        onLiteralValue(false);
        break;
      default:
        return false;
    }
    scanNext();
    return true;
  }
  function parseProperty() {
    if (_scanner.getToken() !== 10) {
      handleError(3, [], [
        2,
        5
        /* SyntaxKind.CommaToken */
      ]);
      return false;
    }
    parseString(false);
    if (_scanner.getToken() === 6) {
      onSeparator(":");
      scanNext();
      if (!parseValue()) {
        handleError(4, [], [
          2,
          5
          /* SyntaxKind.CommaToken */
        ]);
      }
    } else {
      handleError(5, [], [
        2,
        5
        /* SyntaxKind.CommaToken */
      ]);
    }
    _jsonPath.pop();
    return true;
  }
  function parseObject() {
    onObjectBegin();
    scanNext();
    let needsComma = false;
    while (_scanner.getToken() !== 2 && _scanner.getToken() !== 17) {
      if (_scanner.getToken() === 5) {
        if (!needsComma) {
          handleError(4, [], []);
        }
        onSeparator(",");
        scanNext();
        if (_scanner.getToken() === 2 && allowTrailingComma) {
          break;
        }
      } else if (needsComma) {
        handleError(6, [], []);
      }
      if (!parseProperty()) {
        handleError(4, [], [
          2,
          5
          /* SyntaxKind.CommaToken */
        ]);
      }
      needsComma = true;
    }
    onObjectEnd();
    if (_scanner.getToken() !== 2) {
      handleError(7, [
        2
        /* SyntaxKind.CloseBraceToken */
      ], []);
    } else {
      scanNext();
    }
    return true;
  }
  function parseArray() {
    onArrayBegin();
    scanNext();
    let isFirstElement = true;
    let needsComma = false;
    while (_scanner.getToken() !== 4 && _scanner.getToken() !== 17) {
      if (_scanner.getToken() === 5) {
        if (!needsComma) {
          handleError(4, [], []);
        }
        onSeparator(",");
        scanNext();
        if (_scanner.getToken() === 4 && allowTrailingComma) {
          break;
        }
      } else if (needsComma) {
        handleError(6, [], []);
      }
      if (isFirstElement) {
        _jsonPath.push(0);
        isFirstElement = false;
      } else {
        _jsonPath[_jsonPath.length - 1]++;
      }
      if (!parseValue()) {
        handleError(4, [], [
          4,
          5
          /* SyntaxKind.CommaToken */
        ]);
      }
      needsComma = true;
    }
    onArrayEnd();
    if (!isFirstElement) {
      _jsonPath.pop();
    }
    if (_scanner.getToken() !== 4) {
      handleError(8, [
        4
        /* SyntaxKind.CloseBracketToken */
      ], []);
    } else {
      scanNext();
    }
    return true;
  }
  function parseValue() {
    switch (_scanner.getToken()) {
      case 3:
        return parseArray();
      case 1:
        return parseObject();
      case 10:
        return parseString(true);
      default:
        return parseLiteral();
    }
  }
  scanNext();
  if (_scanner.getToken() === 17) {
    if (options.allowEmptyContent) {
      return true;
    }
    handleError(4, [], []);
    return false;
  }
  if (!parseValue()) {
    handleError(4, [], []);
    return false;
  }
  if (_scanner.getToken() !== 17) {
    handleError(9, [], []);
  }
  return true;
}

// node_modules/.pnpm/jsonc-parser@3.3.1/node_modules/jsonc-parser/lib/esm/main.js
var ScanError;
(function(ScanError2) {
  ScanError2[ScanError2["None"] = 0] = "None";
  ScanError2[ScanError2["UnexpectedEndOfComment"] = 1] = "UnexpectedEndOfComment";
  ScanError2[ScanError2["UnexpectedEndOfString"] = 2] = "UnexpectedEndOfString";
  ScanError2[ScanError2["UnexpectedEndOfNumber"] = 3] = "UnexpectedEndOfNumber";
  ScanError2[ScanError2["InvalidUnicode"] = 4] = "InvalidUnicode";
  ScanError2[ScanError2["InvalidEscapeCharacter"] = 5] = "InvalidEscapeCharacter";
  ScanError2[ScanError2["InvalidCharacter"] = 6] = "InvalidCharacter";
})(ScanError || (ScanError = {}));
var SyntaxKind;
(function(SyntaxKind2) {
  SyntaxKind2[SyntaxKind2["OpenBraceToken"] = 1] = "OpenBraceToken";
  SyntaxKind2[SyntaxKind2["CloseBraceToken"] = 2] = "CloseBraceToken";
  SyntaxKind2[SyntaxKind2["OpenBracketToken"] = 3] = "OpenBracketToken";
  SyntaxKind2[SyntaxKind2["CloseBracketToken"] = 4] = "CloseBracketToken";
  SyntaxKind2[SyntaxKind2["CommaToken"] = 5] = "CommaToken";
  SyntaxKind2[SyntaxKind2["ColonToken"] = 6] = "ColonToken";
  SyntaxKind2[SyntaxKind2["NullKeyword"] = 7] = "NullKeyword";
  SyntaxKind2[SyntaxKind2["TrueKeyword"] = 8] = "TrueKeyword";
  SyntaxKind2[SyntaxKind2["FalseKeyword"] = 9] = "FalseKeyword";
  SyntaxKind2[SyntaxKind2["StringLiteral"] = 10] = "StringLiteral";
  SyntaxKind2[SyntaxKind2["NumericLiteral"] = 11] = "NumericLiteral";
  SyntaxKind2[SyntaxKind2["LineCommentTrivia"] = 12] = "LineCommentTrivia";
  SyntaxKind2[SyntaxKind2["BlockCommentTrivia"] = 13] = "BlockCommentTrivia";
  SyntaxKind2[SyntaxKind2["LineBreakTrivia"] = 14] = "LineBreakTrivia";
  SyntaxKind2[SyntaxKind2["Trivia"] = 15] = "Trivia";
  SyntaxKind2[SyntaxKind2["Unknown"] = 16] = "Unknown";
  SyntaxKind2[SyntaxKind2["EOF"] = 17] = "EOF";
})(SyntaxKind || (SyntaxKind = {}));
var parse2 = parse;
var ParseErrorCode;
(function(ParseErrorCode2) {
  ParseErrorCode2[ParseErrorCode2["InvalidSymbol"] = 1] = "InvalidSymbol";
  ParseErrorCode2[ParseErrorCode2["InvalidNumberFormat"] = 2] = "InvalidNumberFormat";
  ParseErrorCode2[ParseErrorCode2["PropertyNameExpected"] = 3] = "PropertyNameExpected";
  ParseErrorCode2[ParseErrorCode2["ValueExpected"] = 4] = "ValueExpected";
  ParseErrorCode2[ParseErrorCode2["ColonExpected"] = 5] = "ColonExpected";
  ParseErrorCode2[ParseErrorCode2["CommaExpected"] = 6] = "CommaExpected";
  ParseErrorCode2[ParseErrorCode2["CloseBraceExpected"] = 7] = "CloseBraceExpected";
  ParseErrorCode2[ParseErrorCode2["CloseBracketExpected"] = 8] = "CloseBracketExpected";
  ParseErrorCode2[ParseErrorCode2["EndOfFileExpected"] = 9] = "EndOfFileExpected";
  ParseErrorCode2[ParseErrorCode2["InvalidCommentToken"] = 10] = "InvalidCommentToken";
  ParseErrorCode2[ParseErrorCode2["UnexpectedEndOfComment"] = 11] = "UnexpectedEndOfComment";
  ParseErrorCode2[ParseErrorCode2["UnexpectedEndOfString"] = 12] = "UnexpectedEndOfString";
  ParseErrorCode2[ParseErrorCode2["UnexpectedEndOfNumber"] = 13] = "UnexpectedEndOfNumber";
  ParseErrorCode2[ParseErrorCode2["InvalidUnicode"] = 14] = "InvalidUnicode";
  ParseErrorCode2[ParseErrorCode2["InvalidEscapeCharacter"] = 15] = "InvalidEscapeCharacter";
  ParseErrorCode2[ParseErrorCode2["InvalidCharacter"] = 16] = "InvalidCharacter";
})(ParseErrorCode || (ParseErrorCode = {}));
function printParseErrorCode(code) {
  switch (code) {
    case 1:
      return "InvalidSymbol";
    case 2:
      return "InvalidNumberFormat";
    case 3:
      return "PropertyNameExpected";
    case 4:
      return "ValueExpected";
    case 5:
      return "ColonExpected";
    case 6:
      return "CommaExpected";
    case 7:
      return "CloseBraceExpected";
    case 8:
      return "CloseBracketExpected";
    case 9:
      return "EndOfFileExpected";
    case 10:
      return "InvalidCommentToken";
    case 11:
      return "UnexpectedEndOfComment";
    case 12:
      return "UnexpectedEndOfString";
    case 13:
      return "UnexpectedEndOfNumber";
    case 14:
      return "InvalidUnicode";
    case 15:
      return "InvalidEscapeCharacter";
    case 16:
      return "InvalidCharacter";
  }
  return "<unknown ParseErrorCode>";
}

// src/paths.ts
import { realpathSync } from "fs";
import { basename as basename2, dirname as dirname2, isAbsolute as isAbsolute2, join as join3, relative, resolve as resolve2, sep } from "path";

// src/engine/allowlist.ts
import { createHash } from "crypto";
function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}
function isAllowedValue(secret, allowlist) {
  if (!allowlist?.sha256?.length) return false;
  const h = sha256(secret);
  return allowlist.sha256.includes(h);
}
function isDisabledRule(ruleId, allowlist) {
  return allowlist?.rules?.includes(ruleId) ?? false;
}
function expandGlobBraces(glob, limit = 64) {
  const open = glob.indexOf("{");
  if (open === -1) return [glob];
  let depth = 0;
  const commas = [];
  let close = -1;
  for (let i = open; i < glob.length; i++) {
    const c = glob[i];
    if (c === "{") depth++;
    else if (c === "}" && --depth === 0) {
      close = i;
      break;
    } else if (c === "," && depth === 1) commas.push(i);
  }
  if (close === -1) return [glob];
  if (commas.length === 0) return expandGlobBraces(glob.slice(close + 1), limit).map((t) => glob.slice(0, close + 1) + t);
  const bounds = [open, ...commas, close];
  const out = [];
  for (let k = 0; k + 1 < bounds.length && out.length < limit; k++) {
    out.push(...expandGlobBraces(glob.slice(0, open) + glob.slice(bounds[k] + 1, bounds[k + 1]) + glob.slice(close + 1), limit));
  }
  return out.slice(0, limit);
}
function tokenizeGlob(glob) {
  const tokens = [];
  for (let i = 0; i < glob.length; ) {
    const c = glob[i];
    if (c === "*" && glob[i + 1] === "*") {
      if (glob[i + 2] === "/") {
        tokens.push({ t: "segments" });
        i += 3;
      } else {
        tokens.push({ t: "any" });
        i += 2;
      }
    } else if (c === "*") {
      tokens.push({ t: "star" });
      i++;
    } else if (c === "?") {
      tokens.push({ t: "one" });
      i++;
    } else {
      tokens.push({ t: "lit", c });
      i++;
    }
  }
  return tokens;
}
function matchTokens(tokens, path) {
  const n = path.length;
  let next = new Uint8Array(n + 2);
  let cur = new Uint8Array(n + 2);
  next[n] = 1;
  for (let i = tokens.length - 1; i >= 0; i--) {
    const tok = tokens[i];
    cur.fill(0);
    let slashAhead = 0;
    for (let j = n; j >= 0; j--) {
      const ch = path[j];
      switch (tok.t) {
        case "lit":
          cur[j] = j < n && ch === tok.c ? next[j + 1] : 0;
          break;
        case "one":
          cur[j] = j < n && ch !== "/" ? next[j + 1] : 0;
          break;
        case "star":
          cur[j] = next[j] || (j < n && ch !== "/" ? cur[j + 1] : 0);
          break;
        case "any":
          cur[j] = next[j] || (j < n ? cur[j + 1] : 0);
          break;
        case "segments":
          if (j < n && ch === "/" && next[j + 1]) slashAhead = 1;
          cur[j] = next[j] || slashAhead;
          break;
      }
    }
    [next, cur] = [cur, next];
  }
  return next[0] === 1;
}
var GLOB_CACHE = /* @__PURE__ */ new Map();
function pathMatchesGlob(path, glob, caseInsensitive = false) {
  const key = `${caseInsensitive ? "i" : "s"}${glob}`;
  let alternatives = GLOB_CACHE.get(key);
  if (!alternatives) {
    const expanded = expandGlobBraces(caseInsensitive ? glob.toLowerCase() : glob).flatMap((g) => g.endsWith("/**") ? [g, g.slice(0, -3)] : [g]);
    alternatives = expanded.map(tokenizeGlob);
    if (GLOB_CACHE.size > 512) GLOB_CACHE.clear();
    GLOB_CACHE.set(key, alternatives);
  }
  const subject = caseInsensitive ? path.toLowerCase() : path;
  return alternatives.some((tokens) => matchTokens(tokens, subject));
}
function isAllowedPath(path, allowlist) {
  if (!path || !allowlist?.paths?.length) return false;
  return allowlist.paths.some((g) => pathMatchesGlob(path, g));
}

// src/shell-paths.ts
import { lstatSync, readdirSync } from "fs";
import { homedir } from "os";
import { basename, dirname, isAbsolute, join, resolve } from "path";
var DYN = "\0";
var SEP_CHARS = /* @__PURE__ */ new Set([";", "&", "|", "(", ")", "\n"]);
function matchParen(s, start) {
  let depth = 1;
  let i = start;
  while (i < s.length) {
    const c = s[i];
    if (c === "\\") i += 2;
    else if (c === "'") {
      const end = s.indexOf("'", i + 1);
      i = end === -1 ? s.length : end + 1;
    } else if (c === '"') {
      i++;
      while (i < s.length && s[i] !== '"') i += s[i] === "\\" ? 2 : 1;
      i++;
    } else if (c === "(") {
      depth++;
      i++;
    } else if (c === ")") {
      if (--depth === 0) return i + 1;
      i++;
    } else i++;
  }
  return s.length;
}
function matchBacktick(s, start) {
  let i = start;
  while (i < s.length && s[i] !== "`") i += s[i] === "\\" ? 2 : 1;
  return Math.min(i + 1, s.length);
}
function innerSubstitutions(text) {
  const out = [];
  for (let i = 0; i < text.length; i++) {
    if (text[i] === "$" && text[i + 1] === "(" && text[i + 2] !== "(") {
      const end = matchParen(text, i + 2);
      out.push(text.slice(i + 2, end - 1));
      i = end - 1;
    } else if (text[i] === "`") {
      const end = matchBacktick(text, i + 1);
      out.push(text.slice(i + 1, end - 1));
      i = end - 1;
    }
  }
  return out;
}
var ANSI_ESCAPES = {
  n: "\n",
  t: "	",
  r: "\r",
  a: "\x07",
  b: "\b",
  e: "\x1B",
  E: "\x1B",
  f: "\f",
  v: "\v",
  "\\": "\\",
  "'": "'",
  '"': '"',
  "?": "?"
};
function ansiC(s, start) {
  let text = "";
  let i = start;
  while (i < s.length && s[i] !== "'") {
    if (s[i] !== "\\") {
      text += s[i];
      i++;
      continue;
    }
    const n = s[i + 1] ?? "";
    const hex = /^x([0-9a-fA-F]{1,2})/.exec(s.slice(i + 1));
    const uni = /^[uU]([0-9a-fA-F]{1,8})/.exec(s.slice(i + 1));
    const oct = /^([0-7]{1,3})/.exec(s.slice(i + 1));
    if (hex) {
      text += String.fromCharCode(Number.parseInt(hex[1], 16));
      i += 1 + hex[0].length;
    } else if (uni) {
      text += String.fromCodePoint(Math.min(Number.parseInt(uni[1], 16), 1114111));
      i += 1 + uni[0].length;
    } else if (oct) {
      text += String.fromCharCode(Number.parseInt(oct[1], 8));
      i += 1 + oct[0].length;
    } else {
      text += ANSI_ESCAPES[n] ?? n;
      i += 2;
    }
  }
  return { text, end: Math.min(i + 1, s.length) };
}
var VAR_RE = /^[A-Za-z_][A-Za-z0-9_]*/;
function tokenize(command, cwd) {
  const st = { commands: [], substitutions: [], dynamic: [], structure: [] };
  let cur = { words: [], redirects: [], stdinLiteral: false };
  let word = "";
  let inWord = false;
  let glob = false;
  let brace = false;
  let pendingRedirect;
  const heredocs = [];
  let i = 0;
  const endWord = () => {
    if (!inWord) return;
    const w = { text: word, glob, brace };
    if (pendingRedirect) {
      cur.redirects.push({ op: pendingRedirect, target: w });
      if (pendingRedirect === "<<" || pendingRedirect === "<<-") {
        heredocs.push({ delim: word.replaceAll(DYN, ""), strip: pendingRedirect === "<<-" });
        cur.stdinLiteral = true;
      }
      if (pendingRedirect === "<<<") cur.stdinLiteral = true;
      pendingRedirect = void 0;
    } else cur.words.push(w);
    word = "";
    inWord = false;
    glob = false;
    brace = false;
  };
  const endCommand = () => {
    endWord();
    if (cur.words.length > 0 || cur.redirects.length > 0) {
      st.structure.push({ type: "cmd", index: st.commands.length });
      st.commands.push(cur);
    }
    cur = { words: [], redirects: [], stdinLiteral: false };
  };
  const expandVar = (name) => {
    if (name === "HOME") return homedir();
    if (name === "PWD") return cwd;
    st.dynamic.push(`$${name}`);
    return DYN;
  };
  while (i < command.length) {
    const c = command[i];
    if (c === "\n" && heredocs.length > 0) {
      endCommand();
      i++;
      for (const { delim, strip } of heredocs.splice(0)) {
        for (; ; ) {
          const nl = command.indexOf("\n", i);
          const line = command.slice(i, nl === -1 ? command.length : nl);
          i = nl === -1 ? command.length : nl + 1;
          if ((strip ? line.replace(/^\t+/, "") : line) === delim || nl === -1) break;
          for (const m of line.matchAll(/\$\(/g)) st.substitutions.push(line.slice(m.index + 2, matchParen(line, m.index + 2) - 1));
        }
      }
      continue;
    }
    if (c === " " || c === "	") {
      endWord();
      i++;
    } else if (c === "#" && !inWord) {
      const nl = command.indexOf("\n", i);
      i = nl === -1 ? command.length : nl;
    } else if (c === "\\") {
      if (command[i + 1] === "\n") {
        i += 2;
      } else {
        word += command[i + 1] ?? "";
        inWord = true;
        i += 2;
      }
    } else if (c === "'") {
      const end = command.indexOf("'", i + 1);
      word += command.slice(i + 1, end === -1 ? command.length : end);
      inWord = true;
      i = end === -1 ? command.length : end + 1;
    } else if (c === '"') {
      inWord = true;
      i++;
      while (i < command.length && command[i] !== '"') {
        const d = command[i];
        if (d === "\\" && i + 1 < command.length && '"\\$`\n'.includes(command[i + 1])) {
          if (command[i + 1] !== "\n") word += command[i + 1];
          i += 2;
        } else if (d === "$" && command[i + 1] === "(") {
          const end = matchParen(command, i + 2);
          st.substitutions.push(command.slice(i + 2, end - 1));
          st.dynamic.push("$(\u2026)");
          word += DYN;
          i = end;
        } else if (d === "`") {
          const end = matchBacktick(command, i + 1);
          st.substitutions.push(command.slice(i + 1, end - 1));
          st.dynamic.push("`\u2026`");
          word += DYN;
          i = end;
        } else if (d === "$" && command[i + 1] === "{") {
          const end = command.indexOf("}", i);
          word += expandVar(command.slice(i + 2, end === -1 ? command.length : end));
          i = end === -1 ? command.length : end + 1;
        } else if (d === "$" && VAR_RE.test(command.slice(i + 1))) {
          const name = VAR_RE.exec(command.slice(i + 1))[0];
          word += expandVar(name);
          i += 1 + name.length;
        } else {
          word += d;
          i++;
        }
      }
      i++;
    } else if (c === "$" && command[i + 1] === "'") {
      const { text, end } = ansiC(command, i + 2);
      word += text;
      inWord = true;
      i = end;
    } else if (c === "$" && command[i + 1] === '"') {
      i++;
    } else if (c === "$" && command[i + 1] === "(") {
      const arithmetic = command[i + 2] === "(";
      const end = matchParen(command, i + 2);
      if (!arithmetic) st.substitutions.push(command.slice(i + 2, end - 1));
      else st.substitutions.push(...innerSubstitutions(command.slice(i + 3, end - 2)));
      st.dynamic.push(arithmetic ? "$((\u2026))" : "$(\u2026)");
      word += DYN;
      inWord = true;
      i = end;
    } else if (c === "$" && command[i + 1] === "{") {
      const end = command.indexOf("}", i);
      word += expandVar(command.slice(i + 2, end === -1 ? command.length : end));
      inWord = true;
      i = end === -1 ? command.length : end + 1;
    } else if (c === "$" && VAR_RE.test(command.slice(i + 1))) {
      const name = VAR_RE.exec(command.slice(i + 1))[0];
      word += expandVar(name);
      inWord = true;
      i += 1 + name.length;
    } else if (c === "$" && /^[0-9@*#?$!-]/.test(command[i + 1] ?? "")) {
      st.dynamic.push(`$${command[i + 1]}`);
      word += DYN;
      inWord = true;
      i += 2;
    } else if (c === "`") {
      const end = matchBacktick(command, i + 1);
      st.substitutions.push(command.slice(i + 1, end - 1));
      st.dynamic.push("`\u2026`");
      word += DYN;
      inWord = true;
      i = end;
    } else if ((c === "<" || c === ">") && command[i + 1] === "(") {
      endWord();
      const end = matchParen(command, i + 2);
      st.substitutions.push(command.slice(i + 2, end - 1));
      i = end;
    } else if (c === "<" || c === ">" || c === "&" && command[i + 1] === ">") {
      if (inWord && /^\d+$/.test(word)) {
        word = "";
        inWord = false;
      }
      endWord();
      const op = /^(?:&>>|&>|<<<|<<-|<<|>>|>\||>&|<&|<>|<|>)/.exec(command.slice(i))[0];
      i += op.length;
      if ((op === ">&" || op === "<&") && /^\s*(?:\d+|-)(?=\s|$|[;&|)])/.test(command.slice(i))) {
        i += /^\s*(?:\d+|-)/.exec(command.slice(i))[0].length;
        continue;
      }
      pendingRedirect = op === ">&" ? ">" : op === "<&" ? "<" : op;
    } else if (c === "(" && command[i + 1] === "(" && !inWord && cur.words.length === 0) {
      endCommand();
      const end = matchParen(command, i + 1);
      st.substitutions.push(...innerSubstitutions(command.slice(i + 2, Math.max(i + 2, end - 2))));
      i = end;
    } else if (SEP_CHARS.has(c)) {
      endCommand();
      if (c === "(") st.structure.push({ type: "open" });
      else if (c === ")") st.structure.push({ type: "close" });
      else if (c === "|" && command[i + 1] !== "|") st.structure.push({ type: "pipe" });
      i += (c === "&" || c === "|" || c === ";") && command[i + 1] === c ? 2 : 1;
    } else {
      if (c === "*" || c === "?" || c === "[") glob = true;
      if (c === "{") brace = true;
      word += c;
      inWord = true;
      i++;
    }
  }
  endCommand();
  return st;
}
function expandBraces(text, limit = 256) {
  const open = text.indexOf("{");
  if (open === -1) return [text];
  let depth = 0;
  const commas = [];
  let close = -1;
  for (let i = open; i < text.length; i++) {
    const c = text[i];
    if (c === "{") depth++;
    else if (c === "}" && --depth === 0) {
      close = i;
      break;
    } else if (c === "," && depth === 1) commas.push(i);
  }
  if (close === -1) return [text];
  const head = text.slice(0, open);
  const tail = text.slice(close + 1);
  if (commas.length === 0) return expandBraces(tail, limit).map((t) => `${text.slice(0, close + 1)}${t}`);
  const bounds = [open, ...commas, close];
  const out = [];
  for (let k = 0; k + 1 < bounds.length; k++) {
    for (const t of expandBraces(`${head}${text.slice(bounds[k] + 1, bounds[k + 1])}${tail}`, limit)) {
      out.push(t);
      if (out.length >= limit) return out;
    }
  }
  return out;
}
function segmentRegex(segment) {
  let re = "";
  for (let i = 0; i < segment.length; i++) {
    const c = segment[i];
    if (c === "*") re += "[^/]*";
    else if (c === "?") re += "[^/]";
    else if (c === "[") {
      const end = segment.indexOf("]", i + 2);
      if (end === -1) re += "\\[";
      else {
        re += `[${segment.slice(i + 1, end).replace(/^!/, "^").replaceAll("\\", "\\\\")}]`;
        i = end;
      }
    } else re += c.replace(/[.+^${}()|\\]/g, "\\$&");
  }
  return new RegExp(`^${re}$`);
}
var GLOB_LIMIT = 2e3;
function expandGlob(absPattern) {
  const parts = absPattern.split("/").filter((p, idx) => p !== "" || idx === 0);
  let frontier = [parts[0] === "" ? "/" : parts[0]];
  for (const part of parts.slice(1)) {
    const next = [];
    const isGlob = /[*?[]/.test(part);
    const re = isGlob ? segmentRegex(part.replaceAll("**", "*")) : void 0;
    for (const dir of frontier) {
      if (!re) {
        next.push(join(dir, part));
        continue;
      }
      let entries;
      try {
        entries = readdirSync(dir);
      } catch {
        continue;
      }
      for (const name of entries) {
        if (name.startsWith(".") && !part.startsWith(".")) continue;
        if (re.test(name)) next.push(join(dir, name));
        if (next.length > GLOB_LIMIT) return { matches: [], overflow: true };
      }
    }
    frontier = next;
  }
  return { matches: frontier.filter((p) => exists(p)), overflow: false };
}
function exists(p) {
  try {
    lstatSync(p);
    return true;
  } catch {
    return false;
  }
}
function expandHome(p) {
  if (p === "~") return homedir();
  if (p.startsWith("~/")) return join(homedir(), p.slice(2));
  return p;
}
var WRAPPERS = /* @__PURE__ */ new Set(["sudo", "env", "time", "nice", "nohup", "command", "builtin", "exec", "timeout", "stdbuf", "ionice", "caffeinate"]);
var NON_PATH_ARGS = /* @__PURE__ */ new Set([
  "echo",
  "printf",
  "print",
  "export",
  "alias",
  "unalias",
  "true",
  "false",
  "sleep",
  "kill",
  "exit",
  "return",
  "set",
  "unset",
  "read",
  "type",
  "which",
  "hash",
  "jobs",
  "wait",
  "shift",
  "trap",
  "ulimit",
  "umask",
  "history"
]);
var WRITE_ARGS = /* @__PURE__ */ new Set(["touch", "mkdir", "rm", "rmdir", "tee", "truncate", "chmod", "chown", "chgrp", "unlink", "shred"]);
var LIST_ARGS = /* @__PURE__ */ new Set(["ls", "dir", "stat", "file", "test", "[", "[[", "wc", "realpath", "readlink", "basename", "dirname"]);
var INTERPRETERS = /^(?:bash|sh|zsh|dash|ksh|fish|python[0-9.]*|node|nodejs|deno|bun|perl|ruby|php|lua|osascript|pwsh|powershell)$/;
var INLINE_FLAGS = /* @__PURE__ */ new Set(["-c", "-e", "-p", "-r", "--eval", "--print", "-E", "eval", "-Command"]);
var SHELLS = /^(?:bash|sh|zsh|dash|ksh)$/;
var EVAL_COMMANDS = /* @__PURE__ */ new Set(["eval", "source", ".", "xargs", "parallel", "watch"]);
var KEYWORDS = /* @__PURE__ */ new Set(["if", "then", "else", "elif", "fi", "do", "done", "while", "until", "!", "{", "}"]);
function commandIndex(words) {
  let k = 0;
  for (; ; ) {
    while (k < words.length && (/^[A-Za-z_][A-Za-z0-9_]*=/.test(words[k].text) || KEYWORDS.has(words[k].text))) k++;
    if (k >= words.length || !WRAPPERS.has(basename(words[k].text))) return k;
    const wrapper = basename(words[k].text);
    k++;
    while (k < words.length && (words[k].text.startsWith("-") || /^[A-Za-z_][A-Za-z0-9_]*=/.test(words[k].text))) k++;
    if (wrapper === "timeout" && k < words.length && /^\d/.test(words[k].text)) k++;
  }
}
function shapeOf(words) {
  const k = commandIndex(words);
  if (k >= words.length) return void 0;
  const cmd = basename(words[k].text);
  const args = [];
  const argWords = [];
  const flags = [];
  let endOfFlags = false;
  for (const w of words.slice(k + 1)) {
    if (!endOfFlags && w.text === "--") {
      endOfFlags = true;
      flags.push("--");
      continue;
    }
    if (!endOfFlags && w.text.startsWith("-") && w.text.length > 1) {
      flags.push(w.text);
      const eq = w.text.indexOf("=");
      if (w.text.startsWith("--") && eq > 0) {
        args.push(w.text.slice(eq + 1));
        argWords.push({ ...w, text: w.text.slice(eq + 1), flagValue: true });
      }
      continue;
    }
    args.push(w.text);
    argWords.push(w);
  }
  return { cmd, args, argWords, flags };
}
var hasFlag = (flags, short, long) => flags.some((f) => long.includes(f.split("=")[0]) || /^-[A-Za-z]+$/.test(f) && short.some((s) => f.includes(s)));
var VALUE_FLAGS = {
  grep: ["-e", "-f", "-m", "-A", "-B", "-C", "--include", "--exclude", "--exclude-dir"],
  rg: ["-e", "-f", "-g", "-t", "-T", "-m", "-A", "-B", "-C", "--glob", "--type", "--max-count"],
  head: ["-n", "-c"],
  tail: ["-n", "-c"],
  sed: ["-e", "-f"],
  awk: ["-f", "-v", "-F"],
  find: [],
  git: ["-C", "-c"],
  // Output files: `openssl genrsa -out server.key` writes, it does not read.
  openssl: ["-out", "-passout"]
};
function positionals(words, cmd) {
  const valued = new Set(VALUE_FLAGS[cmd] ?? []);
  const pos = [];
  let dashAt = -1;
  for (let j = commandIndex(words) + 1; j < words.length; j++) {
    const w = words[j];
    const t = w.text;
    if (dashAt === -1 && t === "--") {
      dashAt = pos.length;
      continue;
    }
    if (dashAt === -1 && t.startsWith("-") && t.length > 1) {
      const eq = t.indexOf("=");
      if (t.startsWith("--") && eq > 0) pos.push({ ...w, text: t.slice(eq + 1), flagValue: true });
      else if (valued.has(t)) j++;
      continue;
    }
    pos.push(w);
  }
  return { pos, dashAt };
}
function explicitPath(text) {
  return text.startsWith("/") || text.startsWith("~") || text.startsWith("./") || text.startsWith("../") || text === "." || text === "..";
}
function analyzeShell(command, opts) {
  const out = { refs: [], commands: [], dynamic: [], unknownCwd: false };
  if (Array.isArray(command)) {
    const [bin, flag, script] = command;
    if (command.length === 3 && typeof bin === "string" && INTERPRETERS.test(basename(bin)) && /^-[a-z]*c$/.test(String(flag)) && typeof script === "string") {
      return analyzeShell(script, opts);
    }
    return analyzeShell(command.map(quoteArg).join(" "), opts);
  }
  analyzeInto(command, opts.cwd, out, 0);
  out.dynamic = [...new Set(out.dynamic)];
  return out;
}
function quoteArg(a) {
  return `'${String(a).replaceAll("'", `'\\''`)}'`;
}
function analyzeInto(command, startCwd, out, depth) {
  if (depth > 8) {
    out.dynamic.push("nested substitution");
    return;
  }
  const st = tokenize(command, startCwd);
  out.dynamic.push(...st.dynamic);
  for (const sub of st.substitutions) analyzeInto(sub, startCwd, out, depth + 1);
  let cwd = startCwd;
  const stack = [];
  let inPipeline = false;
  for (const node of st.structure) {
    if (node.type === "open") {
      stack.push(cwd);
      continue;
    }
    if (node.type === "close") {
      cwd = stack.length > 0 ? stack.pop() : cwd;
      continue;
    }
    if (node.type === "pipe") {
      inPipeline = true;
      continue;
    }
    const sc = st.commands[node.index];
    const next = analyzeCommand(sc, cwd, out, inPipeline);
    inPipeline = false;
    cwd = next;
  }
}
function resolveWord(w, cwd, out) {
  if (w.text.includes(DYN)) return void 0;
  const variants = w.brace ? expandBraces(w.text) : [w.text];
  const paths = [];
  for (const v of variants) {
    if (/^~\+(?:\/|$)/.test(v) && cwd !== void 0) {
      paths.push(resolve(cwd, `.${v.slice(2)}`));
      continue;
    }
    if (/^~[^/]/.test(v)) {
      out.dynamic.push(v.split("/")[0]);
      out.unknownCwd = true;
      return void 0;
    }
    const expanded = expandHome(v);
    if (!isAbsolute(expanded) && cwd === void 0) {
      out.unknownCwd = true;
      return void 0;
    }
    const abs = resolve(cwd ?? "/", expanded);
    if (w.glob && /[*?[]/.test(v)) {
      const g = expandGlob(abs);
      if (g.overflow) {
        paths.push(`${DYN}search:${staticPrefixDir(abs)}`);
      } else paths.push(...g.matches);
    } else paths.push(abs);
  }
  return paths;
}
function staticPrefixDir(abs) {
  const idx = abs.search(/[*?[]/);
  return idx === -1 ? abs : dirname(`${abs.slice(0, idx)}x`);
}
function analyzeCommand(sc, cwd, out, inPipeline) {
  const shape = shapeOf(sc.words);
  const cmd = shape?.cmd ?? "";
  if (sc.words.length > 0) out.commands.push(sc.words.map((w) => w.text));
  const push = (w, kind, force = false, command = cmd, redirect = false) => {
    if (/(?:^|\/)\.\.\.$/.test(w.text)) {
      w = { ...w, text: w.text.replace(/\/?\.\.\.$/, "") || "." };
      kind = "list";
    }
    const paths = resolveWord(w, cwd, out);
    if (!paths) return;
    for (const p of paths) {
      if (p.startsWith(`${DYN}search:`)) {
        out.refs.push({ path: p.slice(`${DYN}search:`.length), kind: "search", raw: w.text, command, explicit: true });
        continue;
      }
      const explicit = force || explicitPath(w.text) || w.glob || exists(p);
      out.refs.push({ path: p, kind, raw: w.text, command, explicit, ...redirect ? { redirect: true } : {} });
    }
  };
  for (const r of sc.redirects) {
    if (r.op === "<<" || r.op === "<<-" || r.op === "<<<") continue;
    const target = r.target.text;
    if (target.includes(DYN)) {
      out.dynamic.push("redirection to a computed path");
      continue;
    }
    if (/^\/dev\/(?:null|stdout|stderr|stdin|tty|zero|u?random|fd\/\d+)$/.test(target)) continue;
    push(r.target, r.op.includes("<") ? "read" : "write", true, cmd, true);
  }
  if (!shape) return cwd;
  if (cmd === "cd" || cmd === "pushd") {
    if (inPipeline) return cwd;
    const target = shape.args[0];
    if (target === void 0) return homedir();
    if (target === "-" || target.includes(DYN)) {
      out.dynamic.push(`${cmd} to a computed directory`);
      return void 0;
    }
    const w = shape.argWords[0];
    const paths = resolveWord(w, cwd, out);
    const next = paths?.length === 1 && !paths[0].startsWith(DYN) ? paths[0] : void 0;
    if (next) out.refs.push({ path: next, kind: "list", raw: target, command: cmd, explicit: true });
    return next;
  }
  if (cmd === "popd") {
    out.dynamic.push("popd");
    return void 0;
  }
  if (EVAL_COMMANDS.has(cmd)) out.dynamic.push(cmd);
  if (INTERPRETERS.test(cmd)) {
    const inline = shape.flags.find((f) => INLINE_FLAGS.has(f) || /^-[a-z]*c$/.test(f));
    if (inline && SHELLS.test(cmd) && /c$/.test(inline) && shape.args[0] !== void 0 && !shape.args[0].includes(DYN)) {
      analyzeInto(shape.args[0], cwd ?? "/", out, 1);
      return cwd;
    }
    if (inline || shape.args[0] === "eval") {
      out.dynamic.push(`${cmd} ${inline ?? "eval"}`);
      const edits = shape.flags.some((f) => /^-[a-zA-Z]*i/.test(f));
      for (const w of shape.argWords.slice(1)) push(w, edits ? "write" : "read");
      return cwd;
    }
    if (shape.args.length === 0 || shape.args[0] === "-") out.dynamic.push(`${cmd} reading a program from stdin`);
    else {
      const script = shape.argWords.find((w) => !w.flagValue);
      for (const w of shape.argWords) push(w, w === script ? "exec" : "read");
      return cwd;
    }
  }
  if (cmd === "find" && shape.flags.some((f) => f === "-exec" || f === "-execdir" || f === "-ok" || f === "-okdir")) out.dynamic.push("find -exec");
  if (NON_PATH_ARGS.has(cmd)) return cwd;
  const words = sc.words;
  const { pos, dashAt } = positionals(words, cmd);
  const flags = shape.flags;
  if (cmd === "git") {
    analyzeGit(pos, dashAt, flags, cwd, out, push);
    return cwd;
  }
  const patternFirst = (cmd === "grep" || cmd === "egrep" || cmd === "fgrep" || cmd === "rg" || cmd === "ag" || cmd === "ack") && !flags.some((f) => f === "-e" || f === "-f" || f.startsWith("--regexp") || f === "--files");
  const targets = patternFirst ? pos.slice(1) : pos;
  const recursive = cmd === "rg" || cmd === "ag" || cmd === "ack" || cmd === "fd" || cmd === "fdfind" || cmd === "find" || cmd === "tree" || cmd === "du" || (cmd === "grep" || cmd === "egrep" || cmd === "fgrep") && hasFlag(flags, ["r", "R"], ["--recursive", "--dereference-recursive"]) || cmd === "ls" && hasFlag(flags, ["R"], ["--recursive"]) || (cmd === "zip" || cmd === "rsync" || cmd === "scp" || cmd === "cp") && hasFlag(flags, ["r", "R", "a"], ["--recursive", "--archive"]) || cmd === "tar" && (hasFlag(flags, ["c"], ["--create"]) || /^c/.test(shape.args[0] ?? ""));
  if (recursive) {
    const explicitTargets = cmd === "find" ? findRoots(words) : targets;
    if (explicitTargets.length === 0 && cwd !== void 0) out.refs.push({ path: cwd, kind: "search", raw: ".", command: cmd, explicit: true });
    else if (explicitTargets.length === 0) out.unknownCwd = true;
    for (const w of explicitTargets) push(w, "search", cmd !== "tar" && cmd !== "zip");
    return cwd;
  }
  if (LIST_ARGS.has(cmd)) {
    if (cmd === "ls" && targets.length === 0) {
      if (cwd !== void 0) out.refs.push({ path: cwd, kind: "list", raw: ".", command: cmd, explicit: true });
      else out.unknownCwd = true;
    }
    for (const w of targets) push(w, "list");
    return cwd;
  }
  if (WRITE_ARGS.has(cmd)) {
    for (const w of targets) push(w, "write");
    return cwd;
  }
  if (cmd === "cp" || cmd === "mv" || cmd === "ln" || cmd === "install") {
    for (const [idx, w] of targets.entries()) push(w, idx === targets.length - 1 && targets.length > 1 ? "write" : "read");
    return cwd;
  }
  const sedInPlace = cmd === "sed" && flags.some((f) => /^-[a-zA-Z]*[iI]/.test(f) || f.startsWith("--in-place"));
  if (cmd === "sed") {
    const files = flags.some((f) => f === "-e" || f === "-f" || f.startsWith("--expression") || f.startsWith("--file")) ? targets : targets.slice(1);
    for (const w of files) push(w, sedInPlace ? "write" : "read");
    return cwd;
  }
  if (cmd === "dd") {
    for (const w of sc.words) {
      const m = /^(if|of)=(.+)$/.exec(w.text);
      if (m) push({ ...w, text: m[2] }, m[1] === "if" ? "read" : "write", true);
    }
    return cwd;
  }
  if (cmd === "awk" || cmd === "gawk") {
    const inPlace = sc.words.some((w) => w.text.includes("inplace"));
    const files = flags.some((f) => f === "-f") ? targets : targets.slice(1);
    for (const w of files) if (!/^inplace(?:\.awk)?$/.test(w.text)) push(w, inPlace ? "write" : "read");
    return cwd;
  }
  if (/^(?:curl|wget|http|https|xh)$/.test(cmd)) {
    for (const w of sc.words) {
      const m = /(?:^|=)@(.+)$/.exec(w.text);
      if (m && !m[1].includes(DYN)) push({ ...w, text: m[1] }, "read", true);
    }
  }
  for (const w of targets) push(w, "read");
  return cwd;
}
function findRoots(words) {
  const roots = [];
  let j = commandIndex(words) + 1;
  while (j < words.length && /^-[HLP]$/.test(words[j].text)) j++;
  for (; j < words.length; j++) {
    const t = words[j].text;
    if (t.startsWith("-") || t === "(" || t === "!") break;
    roots.push(words[j]);
  }
  return roots;
}
var GIT_CONTENT = /* @__PURE__ */ new Set(["diff", "show", "log", "grep", "blame", "annotate", "cat-file", "archive", "format-patch", "whatchanged", "stash"]);
var GIT_NAMES_ONLY = ["--stat", "--name-only", "--name-status", "--numstat", "--shortstat", "--quiet", "--no-patch", "-s", "--summary", "--dirstat"];
var GIT_PATCH = /^(?:-p|-u|--patch|--patch-with-stat|--patch-with-raw|-U\d*|--unified(?:=.*)?|--full-diff|-L.*)$/;
function analyzeGit(pos, dashAt, flags, cwd, out, pushAs) {
  const sub = pos[0]?.text ?? "";
  const rest = pos.slice(1);
  const push = (w, kind, force = false) => pushAs(w, kind, force, `git ${sub}`);
  for (const w of rest) {
    const m = /^[^:\s]*:(.+)$/.exec(w.text);
    if (m && !w.text.includes("://") && (sub === "show" || sub === "cat-file")) push({ ...w, text: m[1] }, "read", true);
  }
  if (!GIT_CONTENT.has(sub)) {
    for (const w of rest) push(w, "list");
    return;
  }
  const patch = flags.some((f) => GIT_PATCH.test(f));
  const namesOnly = !patch && flags.some((f) => GIT_NAMES_ONLY.includes(f.split("=")[0]));
  const logWithoutPatch = (sub === "log" || sub === "whatchanged") && !patch;
  const stashWithoutPatch = sub === "stash" && !(rest[0]?.text === "show" && flags.some((f) => f === "-p" || f === "--patch"));
  if (namesOnly && sub !== "grep" || logWithoutPatch || stashWithoutPatch) {
    for (const w of rest) push(w, "list");
    return;
  }
  const candidates = dashAt !== -1 ? pos.slice(Math.max(dashAt, 1)) : (sub === "grep" ? rest.slice(1) : rest).filter((w) => exists(resolve(cwd ?? "/", expandHome(w.text))));
  const pathspecs = candidates.filter((w) => !w.text.includes(DYN));
  if (pathspecs.length === 0) {
    if (cwd === void 0) out.unknownCwd = true;
    else out.refs.push({ path: cwd, kind: "search", raw: ".", command: `git ${sub}`, explicit: true });
    return;
  }
  for (const w of pathspecs) push(w, "search", true);
}
var JS_RUNTIMES = /^(?:node|nodejs|bun|deno)$/;
var PACKAGE_RUNNERS = /^(?:npx|pnpx|bunx)$/;
function secretgateInvocation(argv) {
  const words = argv.map((text) => ({ text, glob: false, brace: false }));
  let i = commandIndex(words);
  const first = argv[i];
  if (first === void 0) return void 0;
  const skipFlags = (j) => {
    while (j < argv.length && argv[j].startsWith("-")) j++;
    return j;
  };
  const sub = (j) => {
    const k = skipFlags(j);
    const verb = argv[k];
    if (verb === void 0) return void 0;
    const next = argv[skipFlags(k + 1)];
    return verb === "vault" && next ? `vault ${next}` : verb;
  };
  const name = basename(first);
  if (first.includes(DYN)) {
    const verb = sub(i + 1);
    return verb ? `?${verb}` : void 0;
  }
  if (name === "secretgate" || name === "secretgate.mjs") return sub(i + 1);
  if (JS_RUNTIMES.test(name)) {
    const j = skipFlags(i + 1);
    return argv[j] !== void 0 && basename(argv[j]) === "secretgate.mjs" ? sub(j + 1) : void 0;
  }
  if (PACKAGE_RUNNERS.test(name)) i = skipFlags(i + 1) - 1;
  else if (/^(?:pnpm|yarn|npm)$/.test(name) && /^(?:exec|dlx|x)$/.test(argv[i + 1] ?? "")) i = skipFlags(i + 2) - 1;
  else return void 0;
  return /^secretgate(?:@.*)?$/.test(argv[i + 1] ?? "") ? sub(i + 2) : void 0;
}

// src/vault/vault.ts
import { randomBytes } from "crypto";
import { closeSync, mkdirSync, openSync, readFileSync, renameSync, statSync, unlinkSync, writeSync } from "fs";
import { homedir as homedir2 } from "os";
import { join as join2 } from "path";

// src/vault/placeholder.ts
import { createHmac } from "crypto";
function placeholderFor(secret, salt, hexLen = 12) {
  const digest = createHmac("sha256", salt).update(secret).digest("hex");
  return `SECRETGATE_${digest.slice(0, hexLen)}`;
}
var PLACEHOLDER_RE = /SECRETGATE_[0-9a-f]{12,16}/g;

// src/vault/vault.ts
function defaultVaultHome() {
  return process.env.SECRETGATE_HOME ?? join2(homedir2(), ".secretgate");
}
function writeFileAtomic(path, content, mode) {
  const tmp = `${path}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`;
  const fd = openSync(tmp, "w", mode);
  try {
    writeSync(fd, content);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, path);
}
var LOCK_WAIT_MS = 3e3;
var LOCK_STALE_MS = 1e4;
var sleeper = new Int32Array(new SharedArrayBuffer(4));
function withLock(lockPath, fn) {
  const deadline = Date.now() + LOCK_WAIT_MS;
  let fd;
  while (fd === void 0) {
    try {
      fd = openSync(lockPath, "wx", 384);
    } catch (err) {
      if (err.code !== "EEXIST") throw err;
      try {
        if (Date.now() - statSync(lockPath).mtimeMs > LOCK_STALE_MS) unlinkSync(lockPath);
      } catch {
      }
      if (Date.now() > deadline) throw new Error("vault is locked by another secretgate process");
      Atomics.wait(sleeper, 0, 0, 5);
    }
  }
  try {
    return fn();
  } finally {
    closeSync(fd);
    try {
      unlinkSync(lockPath);
    } catch {
    }
  }
}
var Vault = class {
  home;
  vaultPath;
  saltValue;
  constructor(home = defaultVaultHome()) {
    this.home = home;
    this.vaultPath = join2(home, "vault.json");
  }
  ensureHome() {
    mkdirSync(this.home, { recursive: true, mode: 448 });
  }
  salt() {
    if (this.saltValue) return this.saltValue;
    this.ensureHome();
    const saltPath = join2(this.home, "salt");
    try {
      this.saltValue = readFileSync(saltPath, "utf8").trim();
    } catch {
      this.saltValue = randomBytes(32).toString("hex");
      writeFileAtomic(saltPath, this.saltValue, 384);
    }
    if (!this.saltValue) throw new Error(`empty salt file: ${saltPath}`);
    return this.saltValue;
  }
  read() {
    try {
      const parsed = JSON.parse(readFileSync(this.vaultPath, "utf8"));
      if (parsed && parsed.version === 1 && parsed.entries) return parsed;
    } catch {
    }
    return { version: 1, entries: {} };
  }
  // A read-merge-write cycle under the vault lock, so concurrent hook
  // processes (tool calls in flight) never drop each other's entries.
  recordSecret(secret, ruleId, source) {
    this.ensureHome();
    return withLock(`${this.vaultPath}.lock`, () => this.recordLocked(secret, ruleId, source));
  }
  recordLocked(secret, ruleId, source) {
    const salt = this.salt();
    const file = this.read();
    let placeholder = "";
    for (const hexLen of [12, 16]) {
      placeholder = placeholderFor(secret, salt, hexLen);
      const existing = file.entries[placeholder];
      if (!existing || existing.secret === secret) break;
    }
    const entry = file.entries[placeholder];
    if (entry && entry.secret === secret) {
      if (!entry.sources.includes(source)) {
        entry.sources.push(source);
        writeFileAtomic(this.vaultPath, JSON.stringify(file, null, 2), 384);
      }
      return placeholder;
    }
    file.entries[placeholder] = { secret, ruleId, firstSeen: (/* @__PURE__ */ new Date()).toISOString(), sources: [source] };
    writeFileAtomic(this.vaultPath, JSON.stringify(file, null, 2), 384);
    return placeholder;
  }
  secretFor(placeholder) {
    return this.read().entries[placeholder]?.secret;
  }
  list() {
    return Object.entries(this.read().entries).map(([placeholder, e]) => ({
      placeholder,
      ruleId: e.ruleId,
      firstSeen: e.firstSeen,
      sources: e.sources
    }));
  }
  clear() {
    this.ensureHome();
    withLock(`${this.vaultPath}.lock`, () => writeFileAtomic(this.vaultPath, JSON.stringify({ version: 1, entries: {} }, null, 2), 384));
  }
};

// src/paths.ts
var SENSITIVE_GLOBS = [
  "**/.env",
  "**/.env.*",
  "**/*.pem",
  "**/*.key",
  "**/id_rsa*",
  "**/id_ed25519*",
  "**/id_ecdsa*",
  "**/.aws/**",
  "**/.ssh/**",
  "**/.kube/config",
  "**/.npmrc",
  "**/.netrc",
  "**/.docker/config.json",
  "**/credentials.json",
  "**/.envrc",
  "**/.dev.vars",
  "**/.git-credentials",
  "**/.pgpass",
  "**/.pypirc",
  "**/*.p12",
  "**/*.pfx",
  "**/*.tfstate",
  "**/*.tfstate.backup"
];
var FIXTURE_DIRS = /* @__PURE__ */ new Set([
  "test",
  "tests",
  "__tests__",
  "spec",
  "specs",
  "fixture",
  "fixtures",
  "__fixtures__",
  "testdata",
  "test-data",
  "test_data",
  "mocks",
  "__mocks__",
  "examples",
  "samples"
]);
var EXEMPT_GLOBS = ["**/.env.example", "**/.env.sample", "**/.env.template", "**/.env.dist", "**/.env.defaults", "**/*.pub"];
var CASE_INSENSITIVE_FS = process.platform === "darwin" || process.platform === "win32";
function canonical(p) {
  let head = resolve2(expandHome(p));
  const tail = [];
  for (; ; ) {
    try {
      return join3(realpathSync(head), ...[...tail].reverse());
    } catch {
      const parent = dirname2(head);
      if (parent === head) return resolve2(expandHome(p));
      tail.push(basename2(head));
      head = parent;
    }
  }
}
function fold(p) {
  return CASE_INSENSITIVE_FS ? p.toLowerCase() : p;
}
function covers(dir, p) {
  const a = fold(canonical(dir));
  const b = fold(canonical(p));
  return a === b || b.startsWith(a.endsWith(sep) ? a : a + sep);
}
function sensitivePathMatch(path, allowlist, cwd = process.cwd()) {
  const normalized = expandHome(path.replaceAll("\\", "/"));
  const absolute2 = resolve2(cwd, normalized).replaceAll("\\", "/");
  const real = canonical(absolute2).replaceAll("\\", "/");
  const spellings = [.../* @__PURE__ */ new Set([normalized, absolute2, real])];
  const resolvedForms = [absolute2, real, relative(cwd, absolute2).replaceAll("\\", "/"), relative(canonical(cwd), real).replaceAll("\\", "/")];
  if (resolvedForms.some((p) => !p.split("/").includes("..") && isAllowedPath(p, allowlist))) return void 0;
  const vaultHome = defaultVaultHome();
  if (covers(join3(vaultHome, "vault.json"), real) || covers(join3(vaultHome, "salt"), real)) return "secretgate vault";
  const inside = relative(canonical(cwd), real).replaceAll("\\", "/");
  if (!inside.startsWith("../") && inside !== ".." && !isAbsolute2(inside) && inside.split("/").slice(0, -1).some((seg) => FIXTURE_DIRS.has(seg.toLowerCase())))
    return void 0;
  for (const p of spellings) {
    if (EXEMPT_GLOBS.some((g) => pathMatchesGlob(p, g, true))) continue;
    const hit = SENSITIVE_GLOBS.find((g) => pathMatchesGlob(p, g, true));
    if (hit) return hit;
  }
  return void 0;
}
var CONTENT_COMMANDS = /* @__PURE__ */ new Set([
  "cat",
  "head",
  "tail",
  "less",
  "more",
  "bat",
  "batcat",
  "xxd",
  "od",
  "strings",
  "hexdump",
  "nl",
  "tac",
  "base64",
  "base32",
  "sed",
  "awk",
  "gawk",
  "grep",
  "egrep",
  "fgrep",
  "rg",
  "ag",
  "ack",
  "printf",
  "print",
  "sort",
  "uniq",
  "cut",
  "tr",
  "jq",
  "yq",
  "diff",
  "cmp",
  "comm",
  "paste",
  "fold",
  "fmt",
  "column",
  "rev",
  "expand",
  "unexpand",
  "iconv",
  "split",
  "look",
  "cp",
  "install",
  "dd",
  "rsync",
  "scp",
  "tar",
  "zip",
  "gzip",
  "bzip2",
  "xz",
  "zstd",
  "source",
  ".",
  "curl",
  "wget",
  "http",
  "https",
  "xh",
  "nc",
  "ncat",
  "openssl",
  "gpg",
  "vim",
  "vi",
  "nano",
  "emacs"
]);
var GIT_CONTENT2 = /^git (?:show|diff|log|blame|annotate|grep|cat-file|archive|format-patch|whatchanged|stash)$/;
function commandTouchesSensitivePath(command, allowlist, cwd = process.cwd()) {
  const analysis = analyzeShell(command, { cwd });
  for (const ref of analysis.refs) {
    if (ref.kind === "write" || ref.kind === "list" || ref.kind === "exec") continue;
    if (!ref.redirect && !CONTENT_COMMANDS.has(ref.command) && !GIT_CONTENT2.test(ref.command)) continue;
    if (sensitivePathMatch(ref.path, allowlist, cwd)) return ref.raw;
  }
  return void 0;
}

// src/config.ts
function readJsonFile(path) {
  let raw;
  try {
    raw = readFileSync2(path, "utf8");
  } catch {
    return { ok: false, missing: true, message: "unreadable" };
  }
  const errors = [];
  const value = parse2(raw, errors, { allowTrailingComma: true, disallowComments: false });
  if (errors.length > 0) {
    const e = errors[0];
    const line = raw.slice(0, e.offset).split("\n").length;
    return { ok: false, missing: false, message: `not valid JSON: ${printParseErrorCode(e.error)} at line ${line}` };
  }
  return { ok: true, value };
}
var isStringArray = (v) => Array.isArray(v) && v.every((x) => typeof x === "string" && x.trim().length > 0);
function strings(v) {
  return Array.isArray(v) ? v.filter((x) => typeof x === "string" && x.length > 0) : [];
}
function validateAllowlist(v, where) {
  if (v === void 0) return {};
  if (v === null || typeof v !== "object" || Array.isArray(v)) throw new Error(`${where} must be an object`);
  const a = v;
  for (const key of ["sha256", "rules", "paths"]) {
    if (a[key] !== void 0 && !isStringArray(a[key])) throw new Error(`${where}.${key} must be an array of non-empty strings`);
  }
  return { sha256: a.sha256, rules: a.rules, paths: a.paths };
}
function validateScope(v, root, file) {
  if (v === void 0) return void 0;
  if (v === null || typeof v !== "object" || Array.isArray(v)) throw new Error("scope must be an object");
  const s = v;
  for (const key of Object.keys(s))
    if (!["allow", "deny", "bash", "temp"].includes(key)) throw new Error(`scope.${key} is not a known key (allow, deny, bash, temp)`);
  if (s.temp !== void 0 && typeof s.temp !== "boolean") throw new Error("scope.temp must be true or false");
  if (s.allow !== void 0 && !isStringArray(s.allow)) throw new Error("scope.allow must be an array of non-empty glob strings");
  if (s.deny !== void 0 && !isStringArray(s.deny)) throw new Error("scope.deny must be an array of non-empty glob strings");
  if (s.bash !== void 0 && s.bash !== "paths" && s.bash !== "strict") throw new Error('scope.bash must be "paths" or "strict"');
  if (s.allow === void 0 && s.deny === void 0) throw new Error("scope needs an allow or a deny list");
  return {
    root,
    allow: s.allow,
    deny: s.deny,
    bash: s.bash ?? "paths",
    temp: s.temp !== false,
    file
  };
}
function projectConfigFiles(cwd) {
  const files = [];
  const home = resolve3(homedir3());
  let dir = resolve3(cwd);
  for (; ; ) {
    if (dir === home) break;
    const file = join4(dir, ".secretgate.json");
    if (existsSync(file)) files.push(file);
    if (existsSync(join4(dir, ".git"))) break;
    const parent = dirname3(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return files;
}
function loadConfig(cwd) {
  const home = defaultVaultHome();
  const baseRead = readJsonFile(join4(home, "config.json"));
  const base = baseRead.ok && baseRead.value && typeof baseRead.value === "object" ? baseRead.value : {};
  const allowRead = readJsonFile(join4(home, "allowlist.json"));
  const allow = allowRead.ok && allowRead.value && typeof allowRead.value === "object" ? allowRead.value : {};
  const merged = { sha256: strings(allow.sha256), rules: strings(allow.rules), paths: strings(allow.paths) };
  const forScan = { sha256: [...merged.sha256], rules: [...merged.rules], paths: [...merged.paths] };
  const scopes = [];
  const untrusted = [];
  let error;
  const trust = cwd ? readTrust() : {};
  const starts = [cwd, process.env.CLAUDE_PROJECT_DIR].filter((d) => typeof d === "string" && d.length > 0);
  const files = [...new Set(starts.flatMap((d) => projectConfigFiles(d)))];
  for (const file of cwd ? files : []) {
    const read = readJsonFile(file);
    try {
      if (!read.ok) throw new Error(read.message);
      if (read.value === null || typeof read.value !== "object" || Array.isArray(read.value)) throw new Error("must be a JSON object");
      const project = read.value;
      const list = validateAllowlist(project.allowlist, "allowlist");
      const scope = validateScope(project.scope, canonical(dirname3(file)), file);
      const entries = (list.sha256?.length ?? 0) + (list.rules?.length ?? 0) + (list.paths?.length ?? 0);
      const targets = trust[canonical(file)] === fileHash(file) ? [merged, forScan] : [forScan];
      if (entries > 0 && targets.length === 1) untrusted.push(file);
      for (const t of targets) {
        t.sha256.push(...list.sha256 ?? []);
        t.rules.push(...list.rules ?? []);
        t.paths.push(...list.paths ?? []);
      }
      if (scope) scopes.push(scope);
    } catch (err) {
      error ??= { file, message: err instanceof Error ? err.message : String(err) };
    }
  }
  return {
    restoreBash: base.restoreBash === true,
    hybrid: base.hybrid === "off" ? "off" : "auto",
    allowlist: merged,
    scanAllowlist: forScan,
    untrusted,
    scopes,
    ...error ? { error } : {}
  };
}
function trustPath() {
  return join4(defaultVaultHome(), "trusted.json");
}
function fileHash(file) {
  try {
    return createHash2("sha256").update(readFileSync2(file)).digest("hex");
  } catch {
    return void 0;
  }
}
function readTrust() {
  const read = readJsonFile(trustPath());
  if (!read.ok || !read.value || typeof read.value !== "object") return {};
  const files = read.value.files;
  return files && typeof files === "object" && !Array.isArray(files) ? files : {};
}

// src/disable.ts
import { randomBytes as randomBytes2 } from "crypto";
import { closeSync as closeSync2, mkdirSync as mkdirSync3, openSync as openSync2, readFileSync as readFileSync3, renameSync as renameSync3, writeSync as writeSync2 } from "fs";
import { join as join5 } from "path";
var NOT_DISABLED = { disabled: false };
var SESSION_INDEX_MAX = 20;
var MAX_DISABLE_MINUTES = 1440;
function disablePath() {
  return join5(defaultVaultHome(), "disabled.json");
}
function sessionIndexPath() {
  return join5(defaultVaultHome(), "sessions.json");
}
function writeFileAtomic2(path, content, mode) {
  mkdirSync3(defaultVaultHome(), { recursive: true, mode: 448 });
  const tmp = `${path}.${process.pid}.${randomBytes2(4).toString("hex")}.tmp`;
  const fd = openSync2(tmp, "w", mode);
  try {
    writeSync2(fd, content);
  } finally {
    closeSync2(fd);
  }
  renameSync3(tmp, path);
}
function readJson(path) {
  try {
    return JSON.parse(readFileSync3(path, "utf8"));
  } catch {
    return void 0;
  }
}
function emptyDisableFile() {
  return { version: 1, sessions: {}, paths: {} };
}
function readDisableFile() {
  const parsed = readJson(disablePath());
  if (parsed?.version !== 1) return emptyDisableFile();
  return {
    version: 1,
    sessions: isRecord(parsed.sessions) ? parsed.sessions : {},
    paths: isRecord(parsed.paths) ? parsed.paths : {}
  };
}
function isRecord(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}
function isLive(entry, now) {
  if (!entry) return false;
  if (entry.ceiling !== void 0) {
    const ceiling = Date.parse(String(entry.ceiling));
    if (!Number.isFinite(ceiling) || ceiling <= now) return false;
  }
  if (entry.until === null) return true;
  const until = Date.parse(String(entry.until));
  return Number.isFinite(until) && until > now;
}
function prune(file, now) {
  const keepPaths = Object.fromEntries(Object.entries(file.paths).filter(([, e]) => isLive(e, now)));
  const live = liveSessionIds();
  const keepSessions = Object.fromEntries(Object.entries(file.sessions).filter(([id, e]) => isLive(e, now) && !(e.lifetime === true && !live.has(id))));
  return { version: 1, sessions: keepSessions, paths: keepPaths };
}
function liveSessionIds() {
  return new Set(Object.keys(readSessionIndex()));
}
function envDisabled() {
  const raw = (process.env.SECRETGATE_DISABLE ?? "").trim().toLowerCase();
  return raw === "1" || raw === "true" || raw === "yes" || raw === "on";
}
function disableState(ctx = {}) {
  if (envDisabled()) return { disabled: true, scope: "env" };
  const now = Date.now();
  const file = readDisableFile();
  if (ctx.sessionId) {
    const entry = file.sessions[ctx.sessionId];
    if (isLive(entry, now))
      return {
        disabled: true,
        scope: "session",
        until: entry?.until ?? void 0,
        target: ctx.sessionId,
        ...entry?.lifetime ? { lifetime: true } : {},
        ...entry?.liftScope ? { includesScope: true } : {}
      };
  }
  if (ctx.cwd) {
    for (const [dir, entry] of Object.entries(file.paths)) {
      if (isLive(entry, now) && covers(dir, ctx.cwd))
        return { disabled: true, scope: "path", until: entry.until ?? void 0, target: dir, ...entry.liftScope ? { includesScope: true } : {} };
    }
  }
  return NOT_DISABLED;
}
function addPause(req) {
  const now = Date.now();
  const file = prune(readDisableFile(), now);
  const lifetime = req.scope === "session" && req.lifetime === true;
  const until = lifetime || req.minutes === null ? null : new Date(now + Math.min(req.minutes, MAX_DISABLE_MINUTES) * 6e4).toISOString();
  const entry = req.scope === "session" && req.cwd ? { until, cwd: req.cwd } : { until };
  if (req.liftScope) entry.liftScope = true;
  if (lifetime) {
    entry.lifetime = true;
    entry.ceiling = new Date(now + MAX_DISABLE_MINUTES * 6e4).toISOString();
  }
  file[req.scope === "session" ? "sessions" : "paths"][req.target] = entry;
  writeFileAtomic2(disablePath(), JSON.stringify(file, null, 2), 384);
  return until;
}
function removePause(scope, target) {
  const file = prune(readDisableFile(), Date.now());
  const bucket = file[scope === "session" ? "sessions" : "paths"];
  const keys = scope === "path" ? Object.keys(bucket).filter((d) => covers(d, target)) : target in bucket ? [target] : [];
  for (const key of keys) delete bucket[key];
  writeFileAtomic2(disablePath(), JSON.stringify(file, null, 2), 384);
  return keys;
}
function readSessionIndex() {
  const parsed = readJson(sessionIndexPath());
  if (parsed?.version !== 1 || !isRecord(parsed.sessions)) return {};
  return parsed.sessions;
}
var bySeqDesc = (a, b) => (b[1]?.seq ?? 0) - (a[1]?.seq ?? 0);
function recordSession(sessionId, cwd) {
  if (!sessionId || !cwd) return;
  try {
    const sessions = readSessionIndex();
    const maxSeq = Math.max(0, ...Object.values(sessions).map((e) => e?.seq ?? 0));
    if (sessions[sessionId]?.cwd === cwd && sessions[sessionId]?.seq === maxSeq) return;
    const nextSeq = maxSeq + 1;
    sessions[sessionId] = { cwd, lastSeen: (/* @__PURE__ */ new Date()).toISOString(), seq: nextSeq };
    const trimmed = Object.entries(sessions).sort(bySeqDesc).slice(0, SESSION_INDEX_MAX);
    writeFileAtomic2(sessionIndexPath(), JSON.stringify({ version: 1, sessions: Object.fromEntries(trimmed) }, null, 2), 384);
  } catch {
  }
}
function describeDisable(state) {
  if (!state.disabled) return "";
  const where = state.scope === "env" ? "SECRETGATE_DISABLE is set for this process" : state.scope === "session" ? `session ${state.target} is paused` : `directory ${state.target} is paused`;
  const alsoScope = state.includesScope ? " (project scope lifted too)" : "";
  const when = state.until ? ` until ${state.until}` : state.lifetime ? " until the session ends (24 h at most)" : state.scope === "env" ? "" : " until re-enabled";
  return `${where}${when}${alsoScope}`;
}

// src/hooks/policy.ts
import { basename as basename4, resolve as resolve5 } from "path";

// src/scope.ts
import { lstatSync as lstatSync2, readdirSync as readdirSync2, statSync as statSync2 } from "fs";
import { homedir as homedir4, tmpdir } from "os";
import { basename as basename3, dirname as dirname4, isAbsolute as isAbsolute3, join as join6, relative as relative2, resolve as resolve4, sep as sep2 } from "path";
var isOutside = (rel) => rel === ".." || rel.startsWith(`..${sep2}`) || rel.startsWith("../") || isAbsolute3(rel);
var fold2 = (p) => CASE_INSENSITIVE_FS ? p.toLowerCase() : p;
var toPosix = (p) => p.replaceAll("\\", "/");
function absolute(path, cwd) {
  return canonical(resolve4(cwd, expandHome(path)));
}
function relToRoot(scope, abs) {
  const rel = relative2(scope.root, abs);
  if (rel === "") return "";
  if (isOutside(rel)) {
    if (!CASE_INSENSITIVE_FS) return void 0;
    const folded = relative2(fold2(scope.root), fold2(abs));
    if (folded === "" || isOutside(folded)) return folded === "" ? "" : void 0;
    return toPosix(abs.slice(abs.length - folded.length));
  }
  return toPosix(rel);
}
function selfAndAncestors(rel) {
  const parts = rel.split("/");
  return parts.map((_, i) => parts.slice(0, parts.length - i).join("/"));
}
var isAbsoluteGlob = (g) => g.startsWith("/") || g.startsWith("~");
function globMatchesPath(glob, rel, abs) {
  const g = toPosix(glob.replace(/^\.\//, ""));
  if (isAbsoluteGlob(g)) {
    const expanded = toPosix(canonicalGlobBase(expandHome(g)));
    const candidates = selfAndAncestors(toPosix(abs).replace(/^\//, "")).map((p) => `/${p}`);
    return candidates.some((c) => pathMatchesGlob(c, expanded, CASE_INSENSITIVE_FS));
  }
  if (rel === void 0) return false;
  if (rel === "") return g === "." || g === "**" || g === "";
  return selfAndAncestors(rel).some((c) => pathMatchesGlob(c, g, CASE_INSENSITIVE_FS));
}
function canonicalGlobBase(glob) {
  const idx = glob.search(/[*?[{]/);
  if (idx === -1) return canonical(glob);
  const base = glob.slice(0, idx);
  const cut = base.lastIndexOf("/");
  if (cut <= 0) return glob;
  return `${canonical(base.slice(0, cut))}${glob.slice(cut)}`;
}
function staticSegments(glob) {
  const out = [];
  for (const seg of toPosix(glob.replace(/^\.\//, "")).split("/")) {
    if (/[*?[{]/.test(seg) || seg === "") break;
    out.push(seg);
  }
  return out;
}
function describe(rel, abs) {
  return rel === void 0 ? abs : rel === "" ? "the project root" : rel;
}
var tempRoots;
function inTempDir(abs) {
  tempRoots ??= [...new Set([tmpdir(), "/tmp", "/var/tmp"].map((d) => canonical(d)))];
  return tempRoots.some((t) => covers(t, abs));
}
function pathOutOfScope(scope, path, cwd) {
  const abs = absolute(path, cwd);
  const rel = relToRoot(scope, abs);
  const denied = scope.deny?.find((g) => globMatchesPath(g, rel, abs));
  if (denied) return `'${describe(rel, abs)}' matches scope.deny '${denied}'`;
  if (!scope.allow) return void 0;
  if (scope.allow.some((g) => globMatchesPath(g, rel, abs))) return void 0;
  if (rel === void 0 && scope.temp !== false && inTempDir(abs)) return void 0;
  return rel === void 0 ? `'${abs}' is outside the project root ${scope.root}` : `'${describe(rel, abs)}' is not in scope.allow`;
}
function leadsToAllowed(scope, abs) {
  if (!scope.allow) return true;
  const rel = relToRoot(scope, abs);
  return scope.allow.some((g) => {
    if (isAbsoluteGlob(g)) {
      const base = canonicalGlobBase(expandHome(g));
      const idx = base.search(/[*?[{]/);
      return covers(abs, idx === -1 ? base : dirname4(`${base.slice(0, idx)}x`));
    }
    if (rel === void 0) return false;
    if (rel === "") return true;
    const prefix = staticSegments(g);
    const parts = rel.split("/");
    if (prefix.length < parts.length && toPosix(g).slice(prefix.join("/").length).replace(/^\//, "").startsWith("**")) {
      return parts.slice(0, prefix.length).every((p, i) => fold2(p) === fold2(prefix[i]));
    }
    return parts.length <= prefix.length && parts.every((p, i) => fold2(p) === fold2(prefix[i]));
  });
}
function denyBelow(scope, abs) {
  const rel = relToRoot(scope, abs);
  return scope.deny?.find((g) => {
    if (isAbsoluteGlob(g)) {
      const base = canonicalGlobBase(expandHome(g));
      const idx = base.search(/[*?[{]/);
      const staticDir = idx === -1 ? base : dirname4(`${base.slice(0, idx)}x`);
      return covers(abs, staticDir) || covers(staticDir, abs);
    }
    if (rel === void 0) return false;
    const prefix = staticSegments(g);
    if (prefix.length === 0) return true;
    const parts = rel === "" ? [] : rel.split("/");
    const onPrefix = parts.length <= prefix.length && parts.every((p, i) => fold2(p) === fold2(prefix[i]));
    const hasRest = toPosix(g.replace(/^\.\//, "")).split("/").length > parts.length;
    if (onPrefix && (parts.length < prefix.length || hasRest)) return true;
    const rest = toPosix(g).split("/").slice(prefix.length);
    return parts.length > prefix.length && prefix.every((p, i) => fold2(p) === fold2(parts[i])) && rest.some((seg) => seg.includes("**"));
  });
}
var TREE_LIMIT = 2e4;
function treeViolation(scope, dir) {
  let seen = 0;
  const stack = [dir];
  while (stack.length > 0) {
    const current = stack.pop();
    let entries;
    try {
      entries = readdirSync2(current, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      if (++seen > TREE_LIMIT) {
        const below = denyBelow(scope, dir);
        return pathOutOfScope(scope, dir, dir) ?? (below ? `'${describe(relToRoot(scope, dir), dir)}' contains paths matching scope.deny '${below}'` : void 0);
      }
      const full = join6(current, e.name);
      if (e.isDirectory()) {
        const v = pathOutOfScope(scope, full, dir);
        if (v && !leadsToAllowed(scope, canonical(full))) return v;
        stack.push(full);
      } else {
        const v = pathOutOfScope(scope, full, dir);
        if (v) return v;
      }
    }
  }
  return void 0;
}
function isDirectory(abs) {
  try {
    return statSync2(abs).isDirectory();
  } catch {
    return false;
  }
}
function exists2(abs) {
  try {
    lstatSync2(abs);
    return true;
  } catch {
    return false;
  }
}
function accessViolation(scope, path, cwd, kind) {
  const abs = absolute(path, cwd);
  if ((kind === "read" || kind === "list") && fold2(basename3(abs)) === ".secretgate.json") return void 0;
  const out = pathOutOfScope(scope, path, cwd);
  if (kind === "read" || kind === "write") return out;
  if (kind === "list") {
    if (!out) return void 0;
    const rel = relToRoot(scope, abs);
    if (scope.deny?.some((g) => globMatchesPath(g, rel, abs))) return out;
    return leadsToAllowed(scope, abs) ? void 0 : out;
  }
  if (!isDirectory(abs)) return out;
  const v = treeViolation(scope, abs);
  return v ? `${v}, and it is below '${describe(relToRoot(scope, abs), abs)}'` : void 0;
}
var STATE_ENTRIES = ["config.json", "allowlist.json", "disabled.json", "sessions.json", "trusted.json", "vault.json", "salt", "bin", "stopped-sessions"];
function isSecretgateState(abs) {
  const home = defaultVaultHome();
  return STATE_ENTRIES.some((entry) => covers(join6(home, entry), abs));
}
function isPolicyFile(abs, projectRoot) {
  const name = fold2(basename3(abs));
  if (name === ".secretgate.json" || name === "opencode.json" || name === "opencode.jsonc") return true;
  if (fold2(basename3(dirname4(abs))) === ".claude" && /^settings(?:\.[\w-]+)?\.json$/.test(name)) return true;
  const home = homedir4();
  const roots = [process.env.CODEX_HOME ?? join6(home, ".codex"), join6(process.env.XDG_CONFIG_HOME ?? join6(home, ".config"), "opencode")];
  if (projectRoot) roots.push(join6(projectRoot, ".codex"), join6(projectRoot, ".opencode"));
  return isSecretgateState(abs) || roots.some((root) => covers(root, abs));
}
function isControlFile(scope, path, cwd) {
  return isPolicyFile(absolute(path, cwd), scope.root);
}
function controlViolation(scope, path, cwd) {
  return isControlFile(scope, path, cwd) ? `'${path}' configures secretgate or the agent and is read-only while a scope is active (edit it yourself outside the agent)` : void 0;
}
var SAFE_READERS = /* @__PURE__ */ new Set([
  "cat",
  "head",
  "tail",
  "less",
  "more",
  "bat",
  "grep",
  "egrep",
  "fgrep",
  "rg",
  "jq",
  "wc",
  "ls",
  "stat",
  "file",
  "diff",
  "cmp",
  "nl",
  "tree",
  "fd",
  // In-place edits (`sed -i`, `awk -i inplace`) are classified as writes by
  // the analyser, so what reaches here as a read really is one.
  "sed",
  "awk",
  "gawk"
]);
var GIT_READ_ONLY = /^git (?:diff|show|log|blame|annotate|status|grep|ls-files|cat-file|whatchanged|shortlog|add|commit|check-ignore)$/;
function mayModify(ref) {
  return ref.kind === "write" || !(SAFE_READERS.has(ref.command) || GIT_READ_ONLY.test(ref.command));
}
function searchAdvice(scope, refused) {
  const refusedRel = relToRoot(scope, canonical(refused));
  const targets = [...new Set((scope.allow ?? []).map((g) => staticSegments(g).join("/")).filter((p) => p.length > 0 && p !== refusedRel))];
  const usable = targets.filter((t) => isDirectory(join6(scope.root, t)) && !treeViolation(scope, join6(scope.root, t)));
  if (usable.length > 0)
    return ` \u2014 point it at an in-scope directory explicitly (e.g. ${usable.slice(0, 3).map((t) => `${t}/`).join(", ")})`;
  return " \u2014 narrow it to files or subdirectories that are entirely in scope";
}
function shellViolation(scope, command, cwd, workdir) {
  const base = workdir ? resolve4(cwd, expandHome(workdir)) : cwd;
  if (workdir) {
    const v = accessViolation(scope, base, cwd, "list");
    if (v) return `working directory ${v}`;
  }
  const analysis = analyzeShell(command, { cwd: base });
  if (analysis.commands.some((argv) => secretgateInvocation(argv) === "uninstall")) return "uninstalling secretgate is not allowed while a scope is active";
  if (scope.bash === "strict" && analysis.dynamic.length > 0) {
    return `scope.bash is "strict" and this command uses ${analysis.dynamic.slice(0, 3).join(", ")}, which cannot be checked statically \u2014 spell the paths out`;
  }
  if (analysis.unknownCwd) return "this command changes to a directory that cannot be resolved statically, so its relative paths cannot be checked";
  for (const ref of analysis.refs) {
    const v = refViolation(scope, ref, base);
    if (v) return v;
  }
  return void 0;
}
function refViolation(scope, ref, cwd) {
  if (isControlFile(scope, ref.path, cwd) && mayModify(ref)) {
    return `'${ref.raw}' configures secretgate or the agent and is read-only while a scope is active (edit it yourself outside the agent)`;
  }
  if (!ref.explicit) return void 0;
  const strict = scope.bash === "strict";
  let kind;
  if (ref.kind === "exec") {
    if (/^secretgate(?:-opencode)?\.mjs$/.test(basename3(ref.path))) return void 0;
    if (!strict)
      return scope.deny?.some((g) => globMatchesPath(g, relToRoot(scope, absolute(ref.path, cwd)), absolute(ref.path, cwd))) ? pathOutOfScope(scope, ref.path, cwd) : void 0;
    kind = "read";
  } else if (ref.kind === "read" && isDirectory(absolute(ref.path, cwd))) {
    kind = strict ? "search" : "list";
  } else kind = ref.kind;
  const v = accessViolation(scope, ref.path, cwd, kind);
  if (!v) return void 0;
  if (kind === "search")
    return `\`${ref.command}\` would read everything under ${ref.raw === "." ? "the working directory" : `'${ref.raw}'`}: ${v}${searchAdvice(scope, ref.path)}`;
  return v;
}
function searchRootOf(call, cwd) {
  const root = resolve4(cwd, expandHome(call.searchRoot ?? "."));
  const pattern = call.pattern ? expandHome(call.pattern) : "";
  const idx = pattern.search(/[*?[{]/);
  const prefix = idx === -1 ? "" : pattern.slice(0, idx);
  const cut = prefix.lastIndexOf("/");
  return cut === -1 ? root : resolve4(root, prefix.slice(0, cut) || "/");
}
function toolCallScopeViolation(scopes, call, cwd) {
  for (const scope of scopes) {
    const v = oneScope(scope, call, cwd);
    if (v) return `secretgate scope (${scope.file}): ${v}.`;
  }
  return void 0;
}
function oneScope(scope, call, cwd) {
  switch (call.kind) {
    case "read":
      for (const p of call.paths) {
        const v = accessViolation(scope, p, cwd, isDirectory(absolute(p, cwd)) ? "list" : "read");
        if (v) return v;
      }
      return void 0;
    case "write":
    case "patch":
      for (const p of call.paths) {
        const v = controlViolation(scope, p, cwd) ?? accessViolation(scope, p, cwd, "write");
        if (v) return v;
      }
      return void 0;
    case "list":
      for (const p of call.paths.length > 0 ? call.paths : ["."]) {
        const v = accessViolation(scope, p, cwd, "list");
        if (v) return v;
      }
      return void 0;
    case "search": {
      const root = searchRootOf(call, cwd);
      return accessViolation(scope, root, cwd, "list");
    }
    case "shell":
      return call.command === void 0 ? void 0 : shellViolation(scope, call.command, cwd, call.workdir);
    default:
      for (const p of call.paths) {
        const abs = resolve4(cwd, expandHome(p));
        if (!exists2(abs)) continue;
        const v = accessViolation(scope, p, cwd, isDirectory(abs) ? "list" : "read");
        if (v) return v;
      }
      return void 0;
  }
}
function entryOutOfScope(scopes, abs, cwd) {
  const kind = isDirectory(abs) ? "list" : "read";
  return scopes.some((s) => accessViolation(s, abs, cwd, kind) !== void 0);
}
function pathOfLine(line, cwd) {
  const trimmed = line.trim().replace(/^[-*]\s+/, "");
  if (trimmed === "" || trimmed === "--" || trimmed.length > 4096) return void 0;
  const cuts = [trimmed.length];
  for (const m of trimmed.matchAll(/:|-(?=\d+-)/g)) {
    cuts.push(m.index);
    if (cuts.length > 64) break;
  }
  for (const cut of cuts.sort((a, b) => b - a)) {
    const candidate = trimmed.slice(0, cut).trim();
    if (!candidate) continue;
    const abs = resolve4(cwd, expandHome(candidate));
    if (exists2(abs)) return abs;
  }
  return void 0;
}
function lineOutOfScope(scopes, line, cwd) {
  const abs = pathOfLine(line, cwd);
  return abs === void 0 ? void 0 : entryOutOfScope(scopes, abs, cwd);
}
function filterTree(scopes, lines, cwd) {
  const head = lines.findIndex((l) => l.trim() !== "");
  if (head === -1) return void 0;
  const rootText = lines[head].trim().replace(/^[-*]\s+/, "");
  if (!isAbsolute3(rootText) || !isDirectory(rootText)) return void 0;
  const kept = lines.slice(0, head + 1);
  const stack = [{ indent: lines[head].search(/\S/), path: rootText }];
  let dropBelow;
  for (const line of lines.slice(head + 1)) {
    if (line.trim() === "") {
      kept.push(line);
      continue;
    }
    const indent = line.search(/\S/);
    if (dropBelow !== void 0 && indent > dropBelow) continue;
    dropBelow = void 0;
    while (stack.length > 1 && stack[stack.length - 1].indent >= indent) stack.pop();
    const name = line.trim().replace(/^[-*]\s+/, "").replace(/\/$/, "");
    const path = isAbsolute3(name) ? name : join6(stack[stack.length - 1].path, name);
    if (exists2(path) && entryOutOfScope(scopes, path, cwd)) {
      dropBelow = indent;
      continue;
    }
    kept.push(line);
    stack.push({ indent, path });
  }
  return kept;
}
function filterSearchText(scopes, text, cwd) {
  const tree = filterTree(scopes, text.split("\n"), cwd);
  if (tree) return tree.join("\n");
  let dropping = false;
  const kept = [];
  for (const line of text.split("\n")) {
    const indented = /^\s/.test(line) && line.trim() !== "";
    if (!indented) {
      const out = lineOutOfScope(scopes, line, cwd);
      dropping = out === true;
    }
    if (!dropping) kept.push(line);
  }
  return kept.join("\n");
}
function filterSearchOutput(scopes, value, cwd) {
  if (scopes.length === 0) return { value, changed: false };
  if (typeof value === "string") {
    const filtered = filterSearchText(scopes, value, cwd);
    return { value: filtered, changed: filtered !== value };
  }
  if (Array.isArray(value)) {
    let changed = false;
    const next = [];
    for (const item of value) {
      const whole = typeof item === "string" ? resolve4(cwd, expandHome(item)) : void 0;
      const out = whole !== void 0 && exists2(whole) ? entryOutOfScope(scopes, whole, cwd) : typeof item === "string" && lineOutOfScope(scopes, item, cwd) === true;
      if (out) {
        changed = true;
        continue;
      }
      const r = filterSearchOutput(scopes, item, cwd);
      changed ||= r.changed;
      next.push(r.value);
    }
    return { value: next, changed };
  }
  if (value && typeof value === "object") {
    let changed = false;
    const next = {};
    for (const [k, v] of Object.entries(value)) {
      const r = filterSearchOutput(scopes, v, cwd);
      changed ||= r.changed;
      next[k] = r.value;
    }
    if (changed && Array.isArray(next.filenames) && typeof next.numFiles === "number") next.numFiles = next.filenames.length;
    return { value: changed ? next : value, changed };
  }
  return { value, changed: false };
}
function promptMentions(prompt, cwd) {
  const out = [];
  for (const m of prompt.matchAll(/(?:^|[\s(])@("[^"]+"|[^\s,;)'"`]+)/g)) {
    const raw = m[1].replace(/^"|"$/g, "").replace(/[.:]+$/, "");
    const explicit = raw.startsWith("/") || raw.startsWith("~") || raw.startsWith("./") || raw.startsWith("../");
    const abs = resolve4(cwd, expandHome(raw.replace(/#L?\d+(?:-\d+)?$/, "")));
    if (!explicit && !exists2(abs)) continue;
    if (!explicit && !raw.includes("/") && isDirectory(abs)) continue;
    out.push({ raw, abs });
  }
  return out;
}
function promptScopeViolation(scopes, prompt, cwd) {
  if (scopes.length === 0) return void 0;
  for (const { raw, abs } of promptMentions(prompt, cwd)) {
    for (const scope of scopes) {
      const v = accessViolation(scope, abs, cwd, isDirectory(abs) ? "list" : "read");
      if (v) return `secretgate scope (${scope.file}): @${raw} \u2014 ${v}. Mention an in-scope file instead.`;
    }
  }
  return void 0;
}

// src/hooks/policy.ts
function touchesOnly(call, file, cwd) {
  if (call.kind !== "read" && call.kind !== "write" && call.kind !== "patch") return false;
  return call.paths.length > 0 && call.paths.every((p) => canonical(resolve5(cwd, expandHome(p))) === canonical(file));
}
var GUARDED = /* @__PURE__ */ new Set(["disable", "allow", "uninstall", "trust", "vault clear"]);
function tamperReason(call, cwd) {
  if (call.kind === "shell" && call.command !== void 0) {
    const base = call.workdir ? resolve5(cwd, expandHome(call.workdir)) : cwd;
    const analysis = analyzeShell(call.command, { cwd: base });
    for (const argv of analysis.commands) {
      const verb = secretgateInvocation(argv);
      if (verb && GUARDED.has(verb.replace(/^\?/, ""))) {
        return verb.startsWith("?") ? `this runs a program named by a variable with \`${verb.slice(1)}\` \u2014 it may be secretgate, and changing what secretgate protects is your call, not the agent's` : `this runs \`secretgate ${verb}\`, which changes what secretgate protects \u2014 that is your call, not the agent's`;
      }
    }
    for (const ref of analysis.refs) {
      if (ref.kind !== "list" && mayModify(ref) && isPolicyFile(canonical(ref.path), cwd))
        return `this command may change '${ref.raw}', which configures secretgate or its hooks`;
    }
    return void 0;
  }
  if (call.kind === "write" || call.kind === "patch") {
    for (const p of call.paths)
      if (isPolicyFile(canonical(resolve5(cwd, expandHome(p))), cwd)) return `this edits '${p}', which configures secretgate or its hooks`;
  }
  return void 0;
}
function patternLooksSensitive(pattern, root, allowlist, cwd) {
  const name = basename4(pattern);
  for (const probe of [name.replace(/[*?]/g, ""), name.replace(/[*?]/g, "x")]) {
    if (probe && sensitivePathMatch(resolve5(cwd, expandHome(root), probe), allowlist, cwd)) return pattern;
  }
  return void 0;
}
function sensitiveReason(call, cfg, cwd) {
  const deny = (target, hit) => `secretgate: '${target}' looks sensitive (${hit}); its content must not enter the model. If the agent needs a value from it, reference it as an env var instead \u2014 or allow the file with \`secretgate allow --path '${target}'\`.`;
  switch (call.kind) {
    case "read":
    case "other":
      for (const p of call.paths) {
        const hit = sensitivePathMatch(p, cfg.allowlist, cwd);
        if (hit) return deny(p, hit);
      }
      return void 0;
    case "search": {
      if (!call.content) return void 0;
      for (const p of call.paths) {
        const hit = sensitivePathMatch(p, cfg.allowlist, cwd);
        if (hit) return deny(p, hit);
      }
      const pattern = call.pattern ? patternLooksSensitive(call.pattern, call.searchRoot ?? ".", cfg.allowlist, cwd) : void 0;
      return pattern ? deny(pattern, "search pattern naming sensitive files") : void 0;
    }
    case "shell": {
      if (call.command === void 0) return void 0;
      const base = call.workdir ? resolve5(cwd, expandHome(call.workdir)) : cwd;
      const touched = commandTouchesSensitivePath(call.command, cfg.allowlist, base);
      return touched ? `secretgate: this command reads '${touched}', which looks sensitive. Its content must not enter the model.` : void 0;
    }
    default:
      return void 0;
  }
}
function preToolPolicy(call, cfg, cwd, opts) {
  if (cfg.error && !touchesOnly(call, cfg.error.file, cwd)) {
    return {
      action: "deny",
      reason: `secretgate: ${cfg.error.file} is invalid (${cfg.error.message}). Tool calls are refused until it is fixed, because it may declare a scope. Fix it yourself, or let the agent edit it (you will be asked to approve).`
    };
  }
  const scope = toolCallScopeViolation(cfg.scopes, call, cwd);
  if (scope) return { action: "deny", reason: scope };
  if (opts.disabled) return void 0;
  const tamper = tamperReason(call, cwd);
  if (tamper) return { action: "ask", reason: `secretgate: ${tamper}. Approve only if you asked for it.` };
  const sensitive = sensitiveReason(call, cfg, cwd);
  if (sensitive) return { action: "deny", reason: sensitive };
  return void 0;
}

// src/engine/entropy.ts
function shannonEntropy(s) {
  if (s.length === 0) return 0;
  const freq = /* @__PURE__ */ new Map();
  for (const ch of s) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  const len = s.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// src/engine/luhn.ts
function luhnValid(input, options = {}) {
  const s = options.stripSeparators ? input.replace(/[ -]/g, "") : input;
  if (s.length === 0 || !/^\d+$/.test(s)) return false;
  let sum = 0;
  let double = false;
  for (let i = s.length - 1; i >= 0; i--) {
    let digit = s.charCodeAt(i) - 48;
    if (double) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    double = !double;
  }
  return sum % 10 === 0;
}

// src/engine/pragma.ts
var SAME_LINE = /pragma:\s*allowlist\s+secret|gitleaks:allow/;
var NEXT_LINE = /pragma:\s*allowlist\s+nextline\s+secret/;
function pragmaAllowedLines(text) {
  const allowed = /* @__PURE__ */ new Set();
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (NEXT_LINE.test(line)) {
      allowed.add(i + 1);
    } else if (SAME_LINE.test(line)) {
      allowed.add(i);
    }
  }
  return allowed;
}

// src/engine/rules.gen.ts
var RULES = [
  {
    "id": "1password-secret-key",
    "regex": {
      "source": "\\bA3-[A-Z0-9]{6}-(?:(?:[A-Z0-9]{11})|(?:[A-Z0-9]{6}-[A-Z0-9]{5}))-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\\b",
      "flags": ""
    },
    "keywords": [
      "a3-"
    ],
    "entropy": 3.8
  },
  {
    "id": "1password-service-account-token",
    "regex": {
      "source": "ops_eyJ[a-zA-Z0-9+/]{250,}={0,3}",
      "flags": ""
    },
    "keywords": [
      "ops_"
    ],
    "entropy": 4
  },
  {
    "id": "adafruit-api-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:adafruit)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9_-]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "adafruit"
    ]
  },
  {
    "id": "adobe-client-id",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:adobe)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-f0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "adobe"
    ],
    "entropy": 2
  },
  {
    "id": "adobe-client-secret",
    "regex": {
      "source": `\\b(p8e-[a-z0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "p8e-"
    ],
    "entropy": 2
  },
  {
    "id": "age-secret-key",
    "regex": {
      "source": "AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}",
      "flags": ""
    },
    "keywords": [
      "age-secret-key-1"
    ]
  },
  {
    "id": "airtable-api-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:airtable)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{17})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "airtable"
    ]
  },
  {
    "id": "airtable-personnal-access-token",
    "regex": {
      "source": "\\b(pat[[:alnum:]]{14}\\.[a-f0-9]{64})\\b",
      "flags": ""
    },
    "keywords": [
      "airtable"
    ]
  },
  {
    "id": "algolia-api-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:algolia)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "algolia"
    ]
  },
  {
    "id": "alibaba-access-key-id",
    "regex": {
      "source": `\\b(LTAI[a-z0-9]{20})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "ltai"
    ],
    "entropy": 2
  },
  {
    "id": "alibaba-secret-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:alibaba)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{30})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "alibaba"
    ],
    "entropy": 2
  },
  {
    "id": "anthropic-admin-api-key",
    "regex": {
      "source": `\\b(sk-ant-admin01-[a-zA-Z0-9_\\-]{93}AA)(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "sk-ant-admin01"
    ]
  },
  {
    "id": "anthropic-api-key",
    "regex": {
      "source": `\\b(sk-ant-api03-[a-zA-Z0-9_\\-]{93}AA)(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "sk-ant-api03"
    ]
  },
  {
    "id": "artifactory-api-key",
    "regex": {
      "source": "\\bAKCp[A-Za-z0-9]{69}\\b",
      "flags": ""
    },
    "keywords": [
      "akcp"
    ],
    "entropy": 4.5
  },
  {
    "id": "artifactory-reference-token",
    "regex": {
      "source": "\\bcmVmd[A-Za-z0-9]{59}\\b",
      "flags": ""
    },
    "keywords": [
      "cmvmd"
    ],
    "entropy": 4.5
  },
  {
    "id": "asana-client-id",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:asana)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([0-9]{16})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "asana"
    ]
  },
  {
    "id": "asana-client-secret",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:asana)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "asana"
    ]
  },
  {
    "id": "atlassian-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:(?:ATLASSIAN|[Aa]tlassian)|(?:CONFLUENCE|[Cc]onfluence)|(?:JIRA|[Jj]ira))(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{20}[a-f0-9]{4})(?:[\\x60'"\\s;]|\\\\[nr]|$)|\\b(ATATT3[A-Za-z0-9_\\-=]{186})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "atlassian",
      "confluence",
      "jira",
      "atatt3"
    ],
    "entropy": 3.5
  },
  {
    "id": "authress-service-client-access-key",
    "regex": {
      "source": `\\b((?:sc|ext|scauth|authress)_[a-z0-9]{5,30}\\.[a-z0-9]{4,6}\\.(?:acc)[_-][a-z0-9-]{10,32}\\.[a-z0-9+/_=-]{30,120})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "sc_",
      "ext_",
      "scauth_",
      "authress_"
    ],
    "entropy": 2
  },
  {
    "id": "aws-access-token",
    "regex": {
      "source": "\\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\\b",
      "flags": ""
    },
    "keywords": [
      "a3t",
      "akia",
      "asia",
      "abia",
      "acca"
    ],
    "entropy": 3,
    "allowlists": [
      {
        "regexes": [
          {
            "source": ".+EXAMPLE$",
            "flags": ""
          }
        ]
      }
    ]
  },
  {
    "id": "aws-amazon-bedrock-api-key-long-lived",
    "regex": {
      "source": `\\b(ABSK[A-Za-z0-9+/]{109,269}={0,2})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "absk"
    ],
    "entropy": 3
  },
  {
    "id": "aws-amazon-bedrock-api-key-short-lived",
    "regex": {
      "source": "bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t",
      "flags": ""
    },
    "keywords": [
      "bedrock-api-key-"
    ],
    "entropy": 3
  },
  {
    "id": "azure-ad-client-secret",
    "regex": {
      "source": `(?:^|[\\\\'"\\x60\\s>=:(,)])([a-zA-Z0-9_~.]{3}\\dQ~[a-zA-Z0-9_~.-]{31,34})(?:$|[\\\\'"\\x60\\s<),])`,
      "flags": ""
    },
    "keywords": [
      "q~"
    ],
    "entropy": 3
  },
  {
    "id": "beamer-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:beamer)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(b_[a-z0-9=_\\-]{44})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "beamer"
    ]
  },
  {
    "id": "bitbucket-client-id",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:bitbucket)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "bitbucket"
    ]
  },
  {
    "id": "bitbucket-client-secret",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:bitbucket)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9=_\\-]{64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "bitbucket"
    ]
  },
  {
    "id": "bittrex-access-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:bittrex)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "bittrex"
    ]
  },
  {
    "id": "bittrex-secret-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:bittrex)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "bittrex"
    ]
  },
  {
    "id": "cisco-meraki-api-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:[\\w.-]{0,50}?(?:(?:[Mm]eraki|MERAKI))(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([0-9a-f]{40})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "meraki"
    ],
    "entropy": 3
  },
  {
    "id": "clickhouse-cloud-api-secret-key",
    "regex": {
      "source": "\\b(4b1d[A-Za-z0-9]{38})\\b",
      "flags": ""
    },
    "keywords": [
      "4b1d"
    ],
    "entropy": 3
  },
  {
    "id": "clojars-api-token",
    "regex": {
      "source": "CLOJARS_[a-z0-9]{60}",
      "flags": "i"
    },
    "keywords": [
      "clojars_"
    ],
    "entropy": 2
  },
  {
    "id": "cloudflare-api-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:cloudflare)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9_-]{40})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "cloudflare"
    ],
    "entropy": 2
  },
  {
    "id": "cloudflare-global-api-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:cloudflare)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-f0-9]{37})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "cloudflare"
    ],
    "entropy": 2
  },
  {
    "id": "cloudflare-origin-ca-key",
    "regex": {
      "source": `\\b(v1\\.0-[a-f0-9]{24}-[a-f0-9]{146})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "cloudflare",
      "v1.0-"
    ],
    "entropy": 2
  },
  {
    "id": "codecov-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:codecov)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "codecov"
    ]
  },
  {
    "id": "cohere-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:[\\w.-]{0,50}?(?:cohere|CO_API_KEY)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-zA-Z0-9]{40})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "cohere",
      "co_api_key"
    ],
    "entropy": 4
  },
  {
    "id": "coinbase-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:coinbase)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9_-]{64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "coinbase"
    ]
  },
  {
    "id": "confluent-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:confluent)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{16})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "confluent"
    ]
  },
  {
    "id": "confluent-secret-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:confluent)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "confluent"
    ]
  },
  {
    "id": "contentful-delivery-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:contentful)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9=_\\-]{43})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "contentful"
    ]
  },
  {
    "id": "curl-auth-header",
    "regex": {
      "source": `\\bcurl\\b(?:.*?|.*?(?:[\\r\\n]{1,2}.*?){1,5})[ \\t\\n\\r](?:-H|--header)(?:=|[ \\t]{0,5})(?:"(?:Authorization:[ \\t]{0,5}(?:Basic[ \\t]([a-z0-9+/]{8,}={0,3})|(?:Bearer|(?:Api-)?Token)[ \\t]([\\w=~@.+/-]{8,})|([\\w=~@.+/-]{8,}))|(?:(?:X-(?:[a-z]+-)?)?(?:Api-?)?(?:Key|Token)):[ \\t]{0,5}([\\w=~@.+/-]{8,}))"|'(?:Authorization:[ \\t]{0,5}(?:Basic[ \\t]([a-z0-9+/]{8,}={0,3})|(?:Bearer|(?:Api-)?Token)[ \\t]([\\w=~@.+/-]{8,})|([\\w=~@.+/-]{8,}))|(?:(?:X-(?:[a-z]+-)?)?(?:Api-?)?(?:Key|Token)):[ \\t]{0,5}([\\w=~@.+/-]{8,}))')(?:\\B|\\s|$)`,
      "flags": "i"
    },
    "keywords": [
      "curl"
    ],
    "entropy": 2.75
  },
  {
    "id": "curl-auth-user",
    "regex": {
      "source": `\\bcurl\\b(?:.*|.*(?:[\\r\\n]{1,2}.*){1,5})[ \\t\\n\\r](?:-u|--user)(?:=|[ \\t]{0,5})("(:[^"]{3,}|[^:"]{3,}:|[^:"]{3,}:[^"]{3,})"|'([^:']{3,}:[^']{3,})'|((?:"[^"]{3,}"|'[^']{3,}'|[\\w$@.-]+):(?:"[^"]{3,}"|'[^']{3,}'|[\\w\${}@.-]+)))(?:\\s|$)`,
      "flags": ""
    },
    "keywords": [
      "curl"
    ],
    "entropy": 2,
    "allowlists": [
      {
        "regexes": [
          {
            "source": "[^:]+:(?:change(?:it|me)|pass(?:word)?|pwd|test|token|\\*+|x+)",
            "flags": ""
          },
          {
            "source": `['"]?<[^>]+>['"]?:['"]?<[^>]+>|<[^:]+:[^>]+>['"]?`,
            "flags": ""
          },
          {
            "source": "[^:]+:\\[[^]]+]",
            "flags": ""
          },
          {
            "source": `['"]?[^:]+['"]?:['"]?\\$(?:\\d|\\w+|\\{(?:\\d|\\w+)})['"]?`,
            "flags": ""
          },
          {
            "source": "\\$\\([^)]+\\):\\$\\([^)]+\\)",
            "flags": ""
          },
          {
            "source": `['"]?\\$?{{[^}]+}}['"]?:['"]?\\$?{{[^}]+}}['"]?`,
            "flags": ""
          }
        ]
      }
    ]
  },
  {
    "id": "databricks-api-token",
    "regex": {
      "source": `\\b(dapi[a-f0-9]{32}(?:-\\d)?)(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "dapi"
    ],
    "entropy": 3
  },
  {
    "id": "datadog-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:datadog)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{40})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "datadog"
    ]
  },
  {
    "id": "defined-networking-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:dnkey)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(dnkey-[a-z0-9=_\\-]{26}-[a-z0-9=_\\-]{52})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "dnkey"
    ]
  },
  {
    "id": "digitalocean-access-token",
    "regex": {
      "source": `\\b(doo_v1_[a-f0-9]{64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "doo_v1_"
    ],
    "entropy": 3
  },
  {
    "id": "digitalocean-pat",
    "regex": {
      "source": `\\b(dop_v1_[a-f0-9]{64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "dop_v1_"
    ],
    "entropy": 3
  },
  {
    "id": "digitalocean-refresh-token",
    "regex": {
      "source": `\\b(dor_v1_[a-f0-9]{64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "dor_v1_"
    ]
  },
  {
    "id": "discord-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:discord)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-f0-9]{64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "discord"
    ]
  },
  {
    "id": "discord-client-id",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:discord)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([0-9]{18})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "discord"
    ],
    "entropy": 2
  },
  {
    "id": "discord-client-secret",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:discord)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9=_\\-]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "discord"
    ],
    "entropy": 2
  },
  {
    "id": "doppler-api-token",
    "regex": {
      "source": "dp\\.pt\\.[a-z0-9]{43}",
      "flags": "i"
    },
    "keywords": [
      "dp.pt."
    ],
    "entropy": 2
  },
  {
    "id": "droneci-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:droneci)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "droneci"
    ]
  },
  {
    "id": "dropbox-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:dropbox)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{15})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "dropbox"
    ]
  },
  {
    "id": "dropbox-long-lived-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:dropbox)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{11}(AAAAAAAAAA)[a-z0-9\\-_=]{43})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "dropbox"
    ]
  },
  {
    "id": "dropbox-short-lived-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:dropbox)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(sl\\.[a-z0-9\\-=_]{135})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "dropbox"
    ]
  },
  {
    "id": "duffel-api-token",
    "regex": {
      "source": "duffel_(?:test|live)_[a-z0-9_\\-=]{43}",
      "flags": "i"
    },
    "keywords": [
      "duffel_"
    ],
    "entropy": 2
  },
  {
    "id": "dynatrace-api-token",
    "regex": {
      "source": "dt0c01\\.[a-z0-9]{24}\\.[a-z0-9]{64}",
      "flags": "i"
    },
    "keywords": [
      "dt0c01."
    ],
    "entropy": 4
  },
  {
    "id": "easypost-api-token",
    "regex": {
      "source": "\\bEZAK[a-z0-9]{54}\\b",
      "flags": "i"
    },
    "keywords": [
      "ezak"
    ],
    "entropy": 2
  },
  {
    "id": "easypost-test-api-token",
    "regex": {
      "source": "\\bEZTK[a-z0-9]{54}\\b",
      "flags": "i"
    },
    "keywords": [
      "eztk"
    ],
    "entropy": 2
  },
  {
    "id": "etsy-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:(?:ETSY|[Ee]tsy))(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{24})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "etsy"
    ],
    "entropy": 3
  },
  {
    "id": "facebook-access-token",
    "regex": {
      "source": `\\b(\\d{15,16}(\\||%)[0-9a-z\\-_]{27,40})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "facebook"
    ],
    "entropy": 3
  },
  {
    "id": "facebook-page-access-token",
    "regex": {
      "source": `\\b(EAA[MC][a-z0-9]{100,})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "eaam",
      "eaac"
    ],
    "entropy": 4
  },
  {
    "id": "facebook-secret",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:facebook)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-f0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "facebook"
    ],
    "entropy": 3
  },
  {
    "id": "fastly-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:fastly)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9=_\\-]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "fastly"
    ]
  },
  {
    "id": "finicity-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:finicity)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-f0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "finicity"
    ]
  },
  {
    "id": "finicity-client-secret",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:finicity)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{20})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "finicity"
    ]
  },
  {
    "id": "finnhub-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:finnhub)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{20})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "finnhub"
    ]
  },
  {
    "id": "flickr-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:flickr)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "flickr"
    ]
  },
  {
    "id": "flutterwave-encryption-key",
    "regex": {
      "source": "FLWSECK_TEST-[a-h0-9]{12}",
      "flags": "i"
    },
    "keywords": [
      "flwseck_test"
    ],
    "entropy": 2
  },
  {
    "id": "flutterwave-public-key",
    "regex": {
      "source": "FLWPUBK_TEST-[a-h0-9]{32}-X",
      "flags": "i"
    },
    "keywords": [
      "flwpubk_test"
    ],
    "entropy": 2
  },
  {
    "id": "flutterwave-secret-key",
    "regex": {
      "source": "FLWSECK_TEST-[a-h0-9]{32}-X",
      "flags": "i"
    },
    "keywords": [
      "flwseck_test"
    ],
    "entropy": 2
  },
  {
    "id": "flyio-access-token",
    "regex": {
      "source": `\\b((?:fo1_[\\w-]{43}|fm1[ar]_[a-zA-Z0-9+\\/]{100,}={0,3}|fm2_[a-zA-Z0-9+\\/]{100,}={0,3}))(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "fo1_",
      "fm1",
      "fm2_"
    ],
    "entropy": 4
  },
  {
    "id": "frameio-api-token",
    "regex": {
      "source": "fio-u-[a-z0-9\\-_=]{64}",
      "flags": "i"
    },
    "keywords": [
      "fio-u-"
    ]
  },
  {
    "id": "freemius-secret-key",
    "regex": {
      "source": `["']secret_key["']\\s*=>\\s*["'](sk_[\\S]{29})["']`,
      "flags": "i"
    },
    "keywords": [
      "secret_key"
    ],
    "scopePath": {
      "source": "\\.php$",
      "flags": "i"
    }
  },
  {
    "id": "freshbooks-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:freshbooks)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "freshbooks"
    ]
  },
  {
    "id": "gcp-api-key",
    "regex": {
      "source": `\\b(AIza[\\w-]{35})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "aiza"
    ],
    "entropy": 4,
    "allowlists": [
      {
        "regexes": [
          {
            "source": "AIzaSyabcdefghijklmnopqrstuvwxyz1234567",
            "flags": ""
          },
          {
            "source": "AIzaSyAnLA7NfeLquW1tJFpx_eQCxoX-oo6YyIs",
            "flags": ""
          },
          {
            "source": "AIzaSyCkEhVjf3pduRDt6d1yKOMitrUEke8agEM",
            "flags": ""
          },
          {
            "source": "AIzaSyDMAScliyLx7F0NPDEJi1QmyCgHIAODrlU",
            "flags": ""
          },
          {
            "source": "AIzaSyD3asb-2pEZVqMkmL6M9N6nHZRR_znhrh0",
            "flags": ""
          },
          {
            "source": "AIzayDNSXIbFmlXbIE6mCzDLQAqITYefhixbX4A",
            "flags": ""
          },
          {
            "source": "AIzaSyAdOS2zB6NCsk1pCdZ4-P6GBdi_UUPwX7c",
            "flags": ""
          },
          {
            "source": "AIzaSyASWm6HmTMdYWpgMnjRBjxcQ9CKctWmLd4",
            "flags": ""
          },
          {
            "source": "AIzaSyANUvH9H9BsUccjsu2pCmEkOPjjaXeDQgY",
            "flags": ""
          },
          {
            "source": "AIzaSyA5_iVawFQ8ABuTZNUdcwERLJv_a_p4wtM",
            "flags": ""
          },
          {
            "source": "AIzaSyA4UrcGxgwQFTfaI3no3t7Lt1sjmdnP5sQ",
            "flags": ""
          },
          {
            "source": "AIzaSyDSb51JiIcB6OJpwwMicseKRhhrOq1cS7g",
            "flags": ""
          },
          {
            "source": "AIzaSyBF2RrAIm4a0mO64EShQfqfd2AFnzAvvuU",
            "flags": ""
          },
          {
            "source": "AIzaSyBcE-OOIbhjyR83gm4r2MFCu4MJmprNXsw",
            "flags": ""
          },
          {
            "source": "AIzaSyB8qGxt4ec15vitgn44duC5ucxaOi4FmqE",
            "flags": ""
          },
          {
            "source": "AIzaSyA8vmApnrHNFE0bApF4hoZ11srVL_n0nvY",
            "flags": ""
          }
        ]
      }
    ]
  },
  {
    "id": "generic-api-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:access|auth|(?:[Aa]pi|API)|credential|creds|key|passw(?:or)?d|secret|token)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([\\w.=-]{10,150}|[a-z0-9][a-z0-9+/]{11,}={0,3})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "access",
      "api",
      "auth",
      "key",
      "credential",
      "creds",
      "passwd",
      "password",
      "secret",
      "token"
    ],
    "entropy": 3.5,
    "allowlists": [
      {
        "regexes": [
          {
            "source": "^[a-zA-Z_.-]+$",
            "flags": ""
          }
        ]
      },
      {
        "regexTarget": "match",
        "regexes": [
          {
            "source": "(?:access(?:ibility|or)|access[_.-]?id|random[_.-]?access|api[_.-]?(?:id|name|version)|rapid|capital|[a-z0-9-]*?api[a-z0-9-]*?:jar:|author|X-MS-Exchange-Organization-Auth|Authentication-Results|(?:credentials?[_.-]?id|withCredentials)|(?:bucket|foreign|hot|idx|natural|primary|pub(?:lic)?|schema|sequence)[_.-]?key|(?:turkey)|key[_.-]?(?:alias|board|code|frame|id|length|mesh|name|pair|press(?:ed)?|ring|selector|signature|size|stone|storetype|word|up|down|left|right)|key[_.-]?vault[_.-]?(?:id|name)|keyVaultToStoreSecrets|key(?:store|tab)[_.-]?(?:file|path)|issuerkeyhash|(?:[DdMm]onkey|[DM]ONKEY)|keying|(?:secret)[_.-]?(?:length|name|size)|UserSecretsId|(?:csrf)[_.-]?token|(?:io\\.jsonwebtoken[ \\t]?:[ \\t]?[\\w-]+)|(?:api|credentials|token)[_.-]?(?:endpoint|ur[il])|public[_.-]?token|(?:key|token)[_.-]?file|(?:(?:[A-Z_]+=\\n[A-Z_]+=|[a-z_]+=\\n[a-z_]+=)(?:\\n|$))|(?:(?:[A-Z.]+=\\n[A-Z.]+=|[a-z.]+=\\n[a-z.]+=)(?:\\n|$)))",
            "flags": "i"
          }
        ],
        "stopwords": [
          "000000",
          "6fe4476ee5a1832882e326b506d14126",
          "_ec2_",
          "aaaaaa",
          "about",
          "abstract",
          "academy",
          "acces",
          "account",
          "act-",
          "act.",
          "act_",
          "action",
          "active",
          "actively",
          "activity",
          "adapter",
          "add-",
          "add-on",
          "add.",
          "add_",
          "addon",
          "addres",
          "admin",
          "adobe",
          "advanced",
          "adventure",
          "agent",
          "agile",
          "air-",
          "air.",
          "air_",
          "ajax",
          "akka",
          "alert",
          "alfred",
          "algorithm",
          "all-",
          "all.",
          "all_",
          "alloy",
          "alpha",
          "amazon",
          "amqp",
          "analysi",
          "analytic",
          "analyzer",
          "android",
          "angular",
          "angularj",
          "animate",
          "animation",
          "another",
          "ansible",
          "answer",
          "ant-",
          "ant.",
          "ant_",
          "any-",
          "any.",
          "any_",
          "apache",
          "app-",
          "app.",
          "app_",
          "apple",
          "arch",
          "archive",
          "archived",
          "arduino",
          "array",
          "art-",
          "art.",
          "art_",
          "article",
          "asp-",
          "asp.",
          "asp_",
          "asset",
          "async",
          "atom",
          "attention",
          "audio",
          "audit",
          "aura",
          "auth",
          "author",
          "authorize",
          "auto",
          "automated",
          "automatic",
          "awesome",
          "aws_",
          "azure",
          "back",
          "backbone",
          "backend",
          "backup",
          "bar-",
          "bar.",
          "bar_",
          "base",
          "based",
          "bash",
          "basic",
          "batch",
          "been",
          "beer",
          "behavior",
          "being",
          "benchmark",
          "best",
          "beta",
          "better",
          "big-",
          "big.",
          "big_",
          "binary",
          "binding",
          "bit-",
          "bit.",
          "bit_",
          "bitcoin",
          "block",
          "blog",
          "board",
          "book",
          "bookmark",
          "boost",
          "boot",
          "bootstrap",
          "bosh",
          "bot-",
          "bot.",
          "bot_",
          "bower",
          "box-",
          "box.",
          "box_",
          "boxen",
          "bracket",
          "branch",
          "bridge",
          "browser",
          "brunch",
          "buffer",
          "bug-",
          "bug.",
          "bug_",
          "build",
          "builder",
          "building",
          "buildout",
          "buildpack",
          "built",
          "bundle",
          "busines",
          "but-",
          "but.",
          "but_",
          "button",
          "cache",
          "caching",
          "cakephp",
          "calendar",
          "call",
          "camera",
          "campfire",
          "can-",
          "can.",
          "can_",
          "canva",
          "captcha",
          "capture",
          "card",
          "carousel",
          "case",
          "cassandra",
          "cat-",
          "cat.",
          "cat_",
          "category",
          "center",
          "cento",
          "challenge",
          "change",
          "changelog",
          "channel",
          "chart",
          "chat",
          "cheat",
          "check",
          "checker",
          "chef",
          "ches",
          "chinese",
          "chosen",
          "chrome",
          "ckeditor",
          "clas",
          "classe",
          "classic",
          "clean",
          "cli-",
          "cli.",
          "cli_",
          "client",
          "clojure",
          "clone",
          "closure",
          "cloud",
          "club",
          "cluster",
          "cms-",
          "cms_",
          "coco",
          "code",
          "coding",
          "coffee",
          "color",
          "combination",
          "combo",
          "command",
          "commander",
          "comment",
          "commit",
          "common",
          "community",
          "compas",
          "compiler",
          "complete",
          "component",
          "composer",
          "computer",
          "computing",
          "con-",
          "con.",
          "con_",
          "concept",
          "conf",
          "config",
          "connect",
          "connector",
          "console",
          "contact",
          "container",
          "contao",
          "content",
          "contest",
          "context",
          "control",
          "convert",
          "converter",
          "conway'",
          "cookbook",
          "cookie",
          "cool",
          "copy",
          "cordova",
          "core",
          "couchbase",
          "couchdb",
          "countdown",
          "counter",
          "course",
          "craft",
          "crawler",
          "create",
          "creating",
          "creator",
          "credential",
          "crm-",
          "crm.",
          "crm_",
          "cros",
          "crud",
          "csv-",
          "csv.",
          "csv_",
          "cube",
          "cucumber",
          "cuda",
          "current",
          "currently",
          "custom",
          "daemon",
          "dark",
          "dart",
          "dash",
          "dashboard",
          "data",
          "database",
          "date",
          "day-",
          "day.",
          "day_",
          "dead",
          "debian",
          "debug",
          "debugger",
          "deck",
          "define",
          "del-",
          "del.",
          "del_",
          "delete",
          "demo",
          "deploy",
          "design",
          "designer",
          "desktop",
          "detection",
          "detector",
          "dev-",
          "dev.",
          "dev_",
          "develop",
          "developer",
          "device",
          "devise",
          "diff",
          "digital",
          "directive",
          "directory",
          "discovery",
          "display",
          "django",
          "dns-",
          "dns_",
          "doc-",
          "doc.",
          "doc_",
          "docker",
          "docpad",
          "doctrine",
          "document",
          "doe-",
          "doe.",
          "doe_",
          "dojo",
          "dom-",
          "dom.",
          "dom_",
          "domain",
          "don't",
          "done",
          "dot-",
          "dot.",
          "dot_",
          "dotfile",
          "download",
          "draft",
          "drag",
          "drill",
          "drive",
          "driven",
          "driver",
          "drop",
          "dropbox",
          "drupal",
          "dsl-",
          "dsl.",
          "dsl_",
          "dynamic",
          "easy",
          "ecdsa",
          "eclipse",
          "edit",
          "editing",
          "edition",
          "editor",
          "element",
          "emac",
          "email",
          "embed",
          "embedded",
          "ember",
          "emitter",
          "emulator",
          "encoding",
          "endpoint",
          "engine",
          "english",
          "enhanced",
          "entity",
          "entry",
          "env_",
          "episode",
          "erlang",
          "error",
          "espresso",
          "event",
          "evented",
          "example",
          "exchange",
          "exercise",
          "experiment",
          "expire",
          "exploit",
          "explorer",
          "export",
          "exporter",
          "expres",
          "ext-",
          "ext.",
          "ext_",
          "extended",
          "extension",
          "external",
          "extra",
          "extractor",
          "fabric",
          "facebook",
          "factory",
          "fake",
          "fast",
          "feature",
          "feed",
          "fewfwef",
          "ffmpeg",
          "field",
          "file",
          "filter",
          "find",
          "finder",
          "firefox",
          "firmware",
          "first",
          "fish",
          "fix-",
          "fix_",
          "flash",
          "flask",
          "flat",
          "flex",
          "flexible",
          "flickr",
          "flow",
          "fluent",
          "fluentd",
          "fluid",
          "folder",
          "font",
          "force",
          "foreman",
          "fork",
          "form",
          "format",
          "formatter",
          "forum",
          "foundry",
          "framework",
          "free",
          "friend",
          "friendly",
          "front-end",
          "frontend",
          "ftp-",
          "ftp.",
          "ftp_",
          "fuel",
          "full",
          "fun-",
          "fun.",
          "fun_",
          "func",
          "future",
          "gaia",
          "gallery",
          "game",
          "gateway",
          "gem-",
          "gem.",
          "gem_",
          "gen-",
          "gen.",
          "gen_",
          "general",
          "generator",
          "generic",
          "genetic",
          "get-",
          "get.",
          "get_",
          "getenv",
          "getting",
          "ghost",
          "gist",
          "git-",
          "git.",
          "git_",
          "github",
          "gitignore",
          "gitlab",
          "glas",
          "gmail",
          "gnome",
          "gnu-",
          "gnu.",
          "gnu_",
          "goal",
          "golang",
          "gollum",
          "good",
          "google",
          "gpu-",
          "gpu.",
          "gpu_",
          "gradle",
          "grail",
          "graph",
          "graphic",
          "great",
          "grid",
          "groovy",
          "group",
          "grunt",
          "guard",
          "gui-",
          "gui.",
          "gui_",
          "guide",
          "guideline",
          "gulp",
          "gwt-",
          "gwt.",
          "gwt_",
          "hack",
          "hackathon",
          "hacker",
          "hacking",
          "hadoop",
          "haml",
          "handler",
          "hardware",
          "has-",
          "has_",
          "hash",
          "haskell",
          "have",
          "haxe",
          "hello",
          "help",
          "helper",
          "here",
          "hero",
          "heroku",
          "high",
          "hipchat",
          "history",
          "home",
          "homebrew",
          "homepage",
          "hook",
          "host",
          "hosting",
          "hot-",
          "hot.",
          "hot_",
          "house",
          "how-",
          "how.",
          "how_",
          "html",
          "http",
          "hub-",
          "hub.",
          "hub_",
          "hubot",
          "human",
          "icon",
          "ide-",
          "ide.",
          "ide_",
          "idea",
          "identity",
          "idiomatic",
          "image",
          "impact",
          "import",
          "important",
          "importer",
          "impres",
          "index",
          "infinite",
          "info",
          "injection",
          "inline",
          "input",
          "inside",
          "inspector",
          "instagram",
          "install",
          "installer",
          "instant",
          "intellij",
          "interface",
          "internet",
          "interview",
          "into",
          "intro",
          "ionic",
          "iphone",
          "ipython",
          "irc-",
          "irc_",
          "iso-",
          "iso.",
          "iso_",
          "issue",
          "jade",
          "jasmine",
          "java",
          "jbos",
          "jekyll",
          "jenkin",
          "jetbrains",
          "job-",
          "job.",
          "job_",
          "joomla",
          "jpa-",
          "jpa.",
          "jpa_",
          "jquery",
          "json",
          "just",
          "kafka",
          "karma",
          "kata",
          "kernel",
          "keyboard",
          "kindle",
          "kit-",
          "kit.",
          "kit_",
          "kitchen",
          "knife",
          "koan",
          "kohana",
          "lab-",
          "lab.",
          "lab_",
          "lambda",
          "lamp",
          "language",
          "laravel",
          "last",
          "latest",
          "latex",
          "launcher",
          "layer",
          "layout",
          "lazy",
          "ldap",
          "leaflet",
          "league",
          "learn",
          "learning",
          "led-",
          "led.",
          "led_",
          "leetcode",
          "les-",
          "les.",
          "les_",
          "level",
          "leveldb",
          "lib-",
          "lib.",
          "lib_",
          "librarie",
          "library",
          "license",
          "life",
          "liferay",
          "light",
          "lightbox",
          "like",
          "line",
          "link",
          "linked",
          "linkedin",
          "linux",
          "lisp",
          "list",
          "lite",
          "little",
          "load",
          "loader",
          "local",
          "location",
          "lock",
          "log-",
          "log.",
          "log_",
          "logger",
          "logging",
          "logic",
          "login",
          "logstash",
          "longer",
          "look",
          "love",
          "lua-",
          "lua.",
          "lua_",
          "mac-",
          "mac.",
          "mac_",
          "machine",
          "made",
          "magento",
          "magic",
          "mail",
          "make",
          "maker",
          "making",
          "man-",
          "man.",
          "man_",
          "manage",
          "manager",
          "manifest",
          "manual",
          "map-",
          "map.",
          "map_",
          "mapper",
          "mapping",
          "markdown",
          "markup",
          "master",
          "math",
          "matrix",
          "maven",
          "md5",
          "mean",
          "media",
          "mediawiki",
          "meetup",
          "memcached",
          "memory",
          "menu",
          "merchant",
          "message",
          "messaging",
          "meta",
          "metadata",
          "meteor",
          "method",
          "metric",
          "micro",
          "middleman",
          "migration",
          "minecraft",
          "miner",
          "mini",
          "minimal",
          "mirror",
          "mit-",
          "mit.",
          "mit_",
          "mobile",
          "mocha",
          "mock",
          "mod-",
          "mod.",
          "mod_",
          "mode",
          "model",
          "modern",
          "modular",
          "module",
          "modx",
          "money",
          "mongo",
          "mongodb",
          "mongoid",
          "mongoose",
          "monitor",
          "monkey",
          "more",
          "motion",
          "moved",
          "movie",
          "mozilla",
          "mqtt",
          "mule",
          "multi",
          "multiple",
          "music",
          "mustache",
          "mvc-",
          "mvc.",
          "mvc_",
          "mysql",
          "nagio",
          "name",
          "native",
          "need",
          "neo-",
          "neo.",
          "neo_",
          "nest",
          "nested",
          "net-",
          "net.",
          "net_",
          "nette",
          "network",
          "new-",
          "new.",
          "new_",
          "next",
          "nginx",
          "ninja",
          "nlp-",
          "nlp.",
          "nlp_",
          "node",
          "nodej",
          "nosql",
          "not-",
          "not.",
          "not_",
          "note",
          "notebook",
          "notepad",
          "notice",
          "notifier",
          "now-",
          "now.",
          "now_",
          "number",
          "oauth",
          "object",
          "objective",
          "obsolete",
          "ocaml",
          "octopres",
          "official",
          "old-",
          "old.",
          "old_",
          "onboard",
          "online",
          "only",
          "open",
          "opencv",
          "opengl",
          "openshift",
          "openwrt",
          "option",
          "oracle",
          "org-",
          "org.",
          "org_",
          "origin",
          "original",
          "orm-",
          "orm.",
          "orm_",
          "osx-",
          "osx_",
          "our-",
          "our.",
          "our_",
          "out-",
          "out.",
          "out_",
          "output",
          "over",
          "overview",
          "own-",
          "own.",
          "own_",
          "pack",
          "package",
          "packet",
          "page",
          "panel",
          "paper",
          "paperclip",
          "para",
          "parallax",
          "parallel",
          "parse",
          "parser",
          "parsing",
          "particle",
          "party",
          "password",
          "patch",
          "path",
          "pattern",
          "payment",
          "paypal",
          "pdf-",
          "pdf.",
          "pdf_",
          "pebble",
          "people",
          "perl",
          "personal",
          "phalcon",
          "phoenix",
          "phone",
          "phonegap",
          "photo",
          "php-",
          "php.",
          "php_",
          "physic",
          "picker",
          "pipeline",
          "platform",
          "play",
          "player",
          "please",
          "plu-",
          "plu.",
          "plu_",
          "plug-in",
          "plugin",
          "plupload",
          "png-",
          "png.",
          "png_",
          "poker",
          "polyfill",
          "polymer",
          "pool",
          "pop-",
          "pop.",
          "pop_",
          "popcorn",
          "popup",
          "port",
          "portable",
          "portal",
          "portfolio",
          "post",
          "power",
          "powered",
          "powerful",
          "prelude",
          "pretty",
          "preview",
          "principle",
          "print",
          "pro-",
          "pro.",
          "pro_",
          "problem",
          "proc",
          "product",
          "profile",
          "profiler",
          "program",
          "progres",
          "project",
          "protocol",
          "prototype",
          "provider",
          "proxy",
          "public",
          "pull",
          "puppet",
          "pure",
          "purpose",
          "push",
          "pusher",
          "pyramid",
          "python",
          "quality",
          "query",
          "queue",
          "quick",
          "rabbitmq",
          "rack",
          "radio",
          "rail",
          "railscast",
          "random",
          "range",
          "raspberry",
          "rdf-",
          "rdf.",
          "rdf_",
          "react",
          "reactive",
          "read",
          "reader",
          "readme",
          "ready",
          "real",
          "real-time",
          "reality",
          "realtime",
          "recipe",
          "recorder",
          "red-",
          "red.",
          "red_",
          "reddit",
          "redi",
          "redmine",
          "reference",
          "refinery",
          "refresh",
          "registry",
          "related",
          "release",
          "remote",
          "rendering",
          "repo",
          "report",
          "request",
          "require",
          "required",
          "requirej",
          "research",
          "resource",
          "response",
          "resque",
          "rest",
          "restful",
          "resume",
          "reveal",
          "reverse",
          "review",
          "riak",
          "rich",
          "right",
          "ring",
          "robot",
          "role",
          "room",
          "router",
          "routing",
          "rpc-",
          "rpc.",
          "rpc_",
          "rpg-",
          "rpg.",
          "rpg_",
          "rspec",
          "ruby-",
          "ruby.",
          "ruby_",
          "rule",
          "run-",
          "run.",
          "run_",
          "runner",
          "running",
          "runtime",
          "rust",
          "rvm-",
          "rvm.",
          "rvm_",
          "salt",
          "sample",
          "sandbox",
          "sas-",
          "sas.",
          "sas_",
          "sbt-",
          "sbt.",
          "sbt_",
          "scala",
          "scalable",
          "scanner",
          "schema",
          "scheme",
          "school",
          "science",
          "scraper",
          "scratch",
          "screen",
          "script",
          "scroll",
          "scs-",
          "scs.",
          "scs_",
          "sdk-",
          "sdk.",
          "sdk_",
          "sdl-",
          "sdl.",
          "sdl_",
          "search",
          "secure",
          "security",
          "see-",
          "see.",
          "see_",
          "seed",
          "select",
          "selector",
          "selenium",
          "semantic",
          "sencha",
          "send",
          "sentiment",
          "serie",
          "server",
          "service",
          "session",
          "set-",
          "set.",
          "set_",
          "setting",
          "setup",
          "sha1",
          "sha2",
          "sha256",
          "share",
          "shared",
          "sharing",
          "sheet",
          "shell",
          "shield",
          "shipping",
          "shop",
          "shopify",
          "shortener",
          "should",
          "show",
          "showcase",
          "side",
          "silex",
          "simple",
          "simulator",
          "single",
          "site",
          "skeleton",
          "sketch",
          "skin",
          "slack",
          "slide",
          "slider",
          "slim",
          "small",
          "smart",
          "smtp",
          "snake",
          "snapshot",
          "snippet",
          "soap",
          "social",
          "socket",
          "software",
          "solarized",
          "solr",
          "solution",
          "solver",
          "some",
          "soon",
          "source",
          "space",
          "spark",
          "spatial",
          "spec",
          "sphinx",
          "spine",
          "spotify",
          "spree",
          "spring",
          "sprite",
          "sql-",
          "sql.",
          "sql_",
          "sqlite",
          "ssh-",
          "ssh.",
          "ssh_",
          "stack",
          "staging",
          "standard",
          "stanford",
          "start",
          "started",
          "starter",
          "startup",
          "stat",
          "statamic",
          "state",
          "static",
          "statistic",
          "statsd",
          "statu",
          "steam",
          "step",
          "still",
          "stm-",
          "stm.",
          "stm_",
          "storage",
          "store",
          "storm",
          "story",
          "strategy",
          "stream",
          "streaming",
          "string",
          "stripe",
          "structure",
          "studio",
          "study",
          "stuff",
          "style",
          "sublime",
          "sugar",
          "suite",
          "summary",
          "super",
          "support",
          "supported",
          "svg-",
          "svg.",
          "svg_",
          "svn-",
          "svn.",
          "svn_",
          "swagger",
          "swift",
          "switch",
          "switcher",
          "symfony",
          "symphony",
          "sync",
          "synopsi",
          "syntax",
          "system",
          "tab-",
          "tab.",
          "tab_",
          "table",
          "tag-",
          "tag.",
          "tag_",
          "talk",
          "target",
          "task",
          "tcp-",
          "tcp.",
          "tcp_",
          "tdd-",
          "tdd.",
          "tdd_",
          "team",
          "tech",
          "template",
          "term",
          "terminal",
          "testing",
          "tetri",
          "text",
          "textmate",
          "theme",
          "theory",
          "three",
          "thrift",
          "time",
          "timeline",
          "timer",
          "tiny",
          "tinymce",
          "tip-",
          "tip.",
          "tip_",
          "title",
          "todo",
          "todomvc",
          "token",
          "tool",
          "toolbox",
          "toolkit",
          "top-",
          "top.",
          "top_",
          "tornado",
          "touch",
          "tower",
          "tracker",
          "tracking",
          "traffic",
          "training",
          "transfer",
          "translate",
          "transport",
          "tree",
          "trello",
          "try-",
          "try.",
          "try_",
          "tumblr",
          "tut-",
          "tut.",
          "tut_",
          "tutorial",
          "tweet",
          "twig",
          "twitter",
          "type",
          "typo",
          "ubuntu",
          "uiview",
          "ultimate",
          "under",
          "unit",
          "unity",
          "universal",
          "unix",
          "update",
          "updated",
          "upgrade",
          "upload",
          "uploader",
          "uri-",
          "uri.",
          "uri_",
          "url-",
          "url.",
          "url_",
          "usage",
          "usb-",
          "usb.",
          "usb_",
          "use-",
          "use.",
          "use_",
          "used",
          "useful",
          "user",
          "using",
          "util",
          "utilitie",
          "utility",
          "vagrant",
          "validator",
          "value",
          "variou",
          "varnish",
          "version",
          "via-",
          "via.",
          "via_",
          "video",
          "view",
          "viewer",
          "vim-",
          "vim.",
          "vim_",
          "vimrc",
          "virtual",
          "vision",
          "visual",
          "vpn",
          "want",
          "warning",
          "watch",
          "watcher",
          "wave",
          "way-",
          "way.",
          "way_",
          "weather",
          "web-",
          "web_",
          "webapp",
          "webgl",
          "webhook",
          "webkit",
          "webrtc",
          "website",
          "websocket",
          "welcome",
          "what",
          "what'",
          "when",
          "where",
          "which",
          "why-",
          "why.",
          "why_",
          "widget",
          "wifi",
          "wiki",
          "win-",
          "win.",
          "win_",
          "window",
          "wip-",
          "wip.",
          "wip_",
          "within",
          "without",
          "wizard",
          "word",
          "wordpres",
          "work",
          "worker",
          "workflow",
          "working",
          "workshop",
          "world",
          "wrapper",
          "write",
          "writer",
          "writing",
          "written",
          "www-",
          "www.",
          "www_",
          "xamarin",
          "xcode",
          "xml-",
          "xml.",
          "xml_",
          "xmpp",
          "xxxxxx",
          "yahoo",
          "yaml",
          "yandex",
          "yeoman",
          "yet-",
          "yet.",
          "yet_",
          "yii-",
          "yii.",
          "yii_",
          "youtube",
          "yui-",
          "yui.",
          "yui_",
          "zend",
          "zero",
          "zip-",
          "zip.",
          "zip_",
          "zsh-",
          "zsh.",
          "zsh_"
        ]
      },
      {
        "regexTarget": "line",
        "regexes": [
          {
            "source": "--mount=type=secret,",
            "flags": ""
          },
          {
            "source": `import[ \\t]+{[ \\t\\w,]+}[ \\t]+from[ \\t]+['"][^'"]+['"]`,
            "flags": ""
          }
        ]
      },
      {
        "condition": "AND",
        "regexTarget": "line",
        "regexes": [
          {
            "source": 'LICENSE[^=]*=\\s*"[^"]+',
            "flags": ""
          },
          {
            "source": 'LIC_FILES_CHKSUM[^=]*=\\s*"[^"]+',
            "flags": ""
          },
          {
            "source": 'SRC[^=]*=\\s*"[a-zA-Z0-9]+',
            "flags": ""
          }
        ],
        "paths": [
          {
            "source": "\\.bb$",
            "flags": ""
          },
          {
            "source": "\\.bbappend$",
            "flags": ""
          },
          {
            "source": "\\.bbclass$",
            "flags": ""
          },
          {
            "source": "\\.inc$",
            "flags": ""
          }
        ]
      }
    ]
  },
  {
    "id": "github-app-token",
    "regex": {
      "source": "(?:ghu|ghs)_[0-9a-zA-Z]{36}",
      "flags": ""
    },
    "keywords": [
      "ghu_",
      "ghs_"
    ],
    "entropy": 3,
    "allowlists": [
      {
        "paths": [
          {
            "source": "(?:^|/)@octokit/auth-token/README\\.md$",
            "flags": ""
          }
        ]
      }
    ]
  },
  {
    "id": "github-fine-grained-pat",
    "regex": {
      "source": "github_pat_\\w{82}",
      "flags": ""
    },
    "keywords": [
      "github_pat_"
    ],
    "entropy": 3
  },
  {
    "id": "github-oauth",
    "regex": {
      "source": "gho_[0-9a-zA-Z]{36}",
      "flags": ""
    },
    "keywords": [
      "gho_"
    ],
    "entropy": 3
  },
  {
    "id": "github-pat",
    "regex": {
      "source": "ghp_[0-9a-zA-Z]{36}",
      "flags": ""
    },
    "keywords": [
      "ghp_"
    ],
    "entropy": 3,
    "allowlists": [
      {
        "paths": [
          {
            "source": "(?:^|/)@octokit/auth-token/README\\.md$",
            "flags": ""
          }
        ]
      }
    ]
  },
  {
    "id": "github-refresh-token",
    "regex": {
      "source": "ghr_[0-9a-zA-Z]{36}",
      "flags": ""
    },
    "keywords": [
      "ghr_"
    ],
    "entropy": 3
  },
  {
    "id": "gitlab-cicd-job-token",
    "regex": {
      "source": "glcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_-]{20}",
      "flags": ""
    },
    "keywords": [
      "glcbt-"
    ],
    "entropy": 3
  },
  {
    "id": "gitlab-deploy-token",
    "regex": {
      "source": "gldt-[0-9a-zA-Z_\\-]{20}",
      "flags": ""
    },
    "keywords": [
      "gldt-"
    ],
    "entropy": 3
  },
  {
    "id": "gitlab-feature-flag-client-token",
    "regex": {
      "source": "glffct-[0-9a-zA-Z_\\-]{20}",
      "flags": ""
    },
    "keywords": [
      "glffct-"
    ],
    "entropy": 3
  },
  {
    "id": "gitlab-feed-token",
    "regex": {
      "source": "glft-[0-9a-zA-Z_\\-]{20}",
      "flags": ""
    },
    "keywords": [
      "glft-"
    ],
    "entropy": 3
  },
  {
    "id": "gitlab-incoming-mail-token",
    "regex": {
      "source": "glimt-[0-9a-zA-Z_\\-]{25}",
      "flags": ""
    },
    "keywords": [
      "glimt-"
    ],
    "entropy": 3
  },
  {
    "id": "gitlab-kubernetes-agent-token",
    "regex": {
      "source": "glagent-[0-9a-zA-Z_\\-]{50}",
      "flags": ""
    },
    "keywords": [
      "glagent-"
    ],
    "entropy": 3
  },
  {
    "id": "gitlab-oauth-app-secret",
    "regex": {
      "source": "gloas-[0-9a-zA-Z_\\-]{64}",
      "flags": ""
    },
    "keywords": [
      "gloas-"
    ],
    "entropy": 3
  },
  {
    "id": "gitlab-pat",
    "regex": {
      "source": "glpat-[\\w-]{20}",
      "flags": ""
    },
    "keywords": [
      "glpat-"
    ],
    "entropy": 3
  },
  {
    "id": "gitlab-pat-routable",
    "regex": {
      "source": "\\bglpat-[0-9a-zA-Z_-]{27,300}\\.[0-9a-z]{2}[0-9a-z]{7}\\b",
      "flags": ""
    },
    "keywords": [
      "glpat-"
    ],
    "entropy": 4
  },
  {
    "id": "gitlab-ptt",
    "regex": {
      "source": "glptt-[0-9a-f]{40}",
      "flags": ""
    },
    "keywords": [
      "glptt-"
    ],
    "entropy": 3
  },
  {
    "id": "gitlab-rrt",
    "regex": {
      "source": "GR1348941[\\w-]{20}",
      "flags": ""
    },
    "keywords": [
      "gr1348941"
    ],
    "entropy": 3
  },
  {
    "id": "gitlab-runner-authentication-token",
    "regex": {
      "source": "glrt-[0-9a-zA-Z_\\-]{20}",
      "flags": ""
    },
    "keywords": [
      "glrt-"
    ],
    "entropy": 3
  },
  {
    "id": "gitlab-runner-authentication-token-routable",
    "regex": {
      "source": "\\bglrt-t\\d_[0-9a-zA-Z_\\-]{27,300}\\.[0-9a-z]{2}[0-9a-z]{7}\\b",
      "flags": ""
    },
    "keywords": [
      "glrt-"
    ],
    "entropy": 4
  },
  {
    "id": "gitlab-scim-token",
    "regex": {
      "source": "glsoat-[0-9a-zA-Z_\\-]{20}",
      "flags": ""
    },
    "keywords": [
      "glsoat-"
    ],
    "entropy": 3
  },
  {
    "id": "gitlab-session-cookie",
    "regex": {
      "source": "_gitlab_session=[0-9a-z]{32}",
      "flags": ""
    },
    "keywords": [
      "_gitlab_session="
    ],
    "entropy": 3
  },
  {
    "id": "gitter-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:gitter)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9_-]{40})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "gitter"
    ]
  },
  {
    "id": "gocardless-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:gocardless)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(live_[a-z0-9\\-_=]{40})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "live_",
      "gocardless"
    ]
  },
  {
    "id": "grafana-api-key",
    "regex": {
      "source": `\\b(eyJrIjoi[A-Za-z0-9]{70,400}={0,3})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "eyjrijoi"
    ],
    "entropy": 3
  },
  {
    "id": "grafana-cloud-api-token",
    "regex": {
      "source": `\\b(glc_[A-Za-z0-9+/]{32,400}={0,3})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "glc_"
    ],
    "entropy": 3
  },
  {
    "id": "grafana-service-account-token",
    "regex": {
      "source": `\\b(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "glsa_"
    ],
    "entropy": 3
  },
  {
    "id": "harness-api-key",
    "regex": {
      "source": "(?:pat|sat)\\.[a-zA-Z0-9_-]{22}\\.[a-zA-Z0-9]{24}\\.[a-zA-Z0-9]{20}",
      "flags": ""
    },
    "keywords": [
      "pat.",
      "sat."
    ]
  },
  {
    "id": "hashicorp-tf-api-token",
    "regex": {
      "source": "[a-z0-9]{14}\\.(?:atlasv1)\\.[a-z0-9\\-_=]{60,70}",
      "flags": "i"
    },
    "keywords": [
      "atlasv1"
    ],
    "entropy": 3.5
  },
  {
    "id": "hashicorp-tf-password",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:administrator_login_password|password)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}("[a-z0-9=_\\-]{8,20}")(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "administrator_login_password",
      "password"
    ],
    "entropy": 2,
    "scopePath": {
      "source": "\\.(?:tf|hcl)$",
      "flags": "i"
    }
  },
  {
    "id": "heroku-api-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:heroku)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "heroku"
    ]
  },
  {
    "id": "heroku-api-key-v2",
    "regex": {
      "source": `\\b((HRKU-AA[0-9a-zA-Z_-]{58}))(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "hrku-aa"
    ],
    "entropy": 4
  },
  {
    "id": "hubspot-api-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:hubspot)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "hubspot"
    ]
  },
  {
    "id": "huggingface-access-token",
    "regex": {
      "source": `\\b(hf_(?:[a-z]{34}))(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "hf_"
    ],
    "entropy": 2
  },
  {
    "id": "huggingface-organization-api-token",
    "regex": {
      "source": `\\b(api_org_(?:[a-z]{34}))(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "api_org_"
    ],
    "entropy": 2
  },
  {
    "id": "infracost-api-token",
    "regex": {
      "source": `\\b(ico-[a-zA-Z0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "ico-"
    ],
    "entropy": 3
  },
  {
    "id": "intercom-api-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:intercom)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9=_\\-]{60})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "intercom"
    ]
  },
  {
    "id": "intra42-client-secret",
    "regex": {
      "source": `\\b(s-s4t2(?:ud|af)-[abcdef0123456789]{64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "intra",
      "s-s4t2ud-",
      "s-s4t2af-"
    ],
    "entropy": 3
  },
  {
    "id": "jfrog-api-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:jfrog|artifactory|bintray|xray)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{73})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "jfrog",
      "artifactory",
      "bintray",
      "xray"
    ]
  },
  {
    "id": "jfrog-identity-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:jfrog|artifactory|bintray|xray)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "jfrog",
      "artifactory",
      "bintray",
      "xray"
    ]
  },
  {
    "id": "jwt",
    "regex": {
      "source": `\\b(ey[a-zA-Z0-9]{17,}\\.ey[a-zA-Z0-9\\/\\\\_-]{17,}\\.(?:[a-zA-Z0-9\\/\\\\_-]{10,}={0,2})?)(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "ey"
    ],
    "entropy": 3
  },
  {
    "id": "jwt-base64",
    "regex": {
      "source": "\\bZXlK(?:(?<alg>aGJHY2lPaU)|(?<apu>aGNIVWlPaU)|(?<apv>aGNIWWlPaU)|(?<aud>aGRXUWlPaU)|(?<b64>aU5qUWlP)|(?<crit>amNtbDBJanBi)|(?<cty>amRIa2lPaU)|(?<epk>bGNHc2lPbn)|(?<enc>bGJtTWlPaU)|(?<jku>cWEzVWlPaU)|(?<jwk>cWQyc2lPb)|(?<iss>cGMzTWlPaU)|(?<iv>cGRpSTZJ)|(?<kid>cmFXUWlP)|(?<key_ops>clpYbGZiM0J6SWpwY)|(?<kty>cmRIa2lPaUp)|(?<nonce>dWIyNWpaU0k2)|(?<p2c>d01tTWlP)|(?<p2s>d01uTWlPaU)|(?<ppt>d2NIUWlPaU)|(?<sub>emRXSWlPaU)|(?<svt>emRuUWlP)|(?<tag>MFlXY2lPaU)|(?<typ>MGVYQWlPaUp)|(?<url>MWNtd2l)|(?<use>MWMyVWlPaUp)|(?<ver>MlpYSWlPaU)|(?<version>MlpYSnphVzl1SWpv)|(?<x>NElqb2)|(?<x5c>NE5XTWlP)|(?<x5t>NE5YUWlPaU)|(?<x5ts256>NE5YUWpVekkxTmlJNkl)|(?<x5u>NE5YVWlPaU)|(?<zip>NmFYQWlPaU))[a-zA-Z0-9\\/\\\\_+\\-\\r\\n]{40,}={0,2}",
      "flags": ""
    },
    "keywords": [
      "zxlk"
    ],
    "entropy": 2
  },
  {
    "id": "kraken-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:kraken)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9\\/=_\\+\\-]{80,90})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "kraken"
    ]
  },
  {
    "id": "kubernetes-secret-yaml",
    "regex": {
      "source": `(?:\\bkind:[ \\t]*["']?\\bsecret\\b["']?(?:[\\s\\S]){0,200}?\\bdata:(?:[\\s\\S]){0,100}?\\s+([\\w.-]+:(?:[ \\t]*(?:\\||>[-+]?)\\s+)?[ \\t]*(?:["']?[a-z0-9+/]{10,}={0,3}["']?|\\{\\{[ \\t\\w"|$:=,.-]+}}|""|''))|\\bdata:(?:[\\s\\S]){0,100}?\\s+([\\w.-]+:(?:[ \\t]*(?:\\||>[-+]?)\\s+)?[ \\t]*(?:["']?[a-z0-9+/]{10,}={0,3}["']?|\\{\\{[ \\t\\w"|$:=,.-]+}}|""|''))(?:[\\s\\S]){0,200}?\\bkind:[ \\t]*["']?\\bsecret\\b["']?)`,
      "flags": "i"
    },
    "keywords": [
      "secret"
    ],
    "scopePath": {
      "source": "\\.ya?ml$",
      "flags": "i"
    },
    "allowlists": [
      {
        "regexes": [
          {
            "source": `[\\w.-]+:(?:[ \\t]*(?:\\||>[-+]?)\\s+)?[ \\t]*(?:\\{\\{[ \\t\\w"|$:=,.-]+}}|""|'')`,
            "flags": ""
          }
        ]
      },
      {
        "regexTarget": "match",
        "regexes": [
          {
            "source": "(kind:(?:[\\s\\S])+\\n---\\n(?:[\\s\\S])+\\bdata:|data:(?:[\\s\\S])+\\n---\\n(?:[\\s\\S])+\\bkind:)",
            "flags": ""
          }
        ]
      }
    ]
  },
  {
    "id": "kucoin-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:kucoin)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-f0-9]{24})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "kucoin"
    ]
  },
  {
    "id": "kucoin-secret-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:kucoin)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "kucoin"
    ]
  },
  {
    "id": "launchdarkly-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:launchdarkly)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9=_\\-]{40})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "launchdarkly"
    ]
  },
  {
    "id": "linear-api-key",
    "regex": {
      "source": "lin_api_[a-z0-9]{40}",
      "flags": "i"
    },
    "keywords": [
      "lin_api_"
    ],
    "entropy": 2
  },
  {
    "id": "linear-client-secret",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:linear)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-f0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "linear"
    ],
    "entropy": 2
  },
  {
    "id": "linkedin-client-id",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:linked[_-]?in)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{14})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "linkedin",
      "linked_in",
      "linked-in"
    ],
    "entropy": 2
  },
  {
    "id": "linkedin-client-secret",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:linked[_-]?in)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{16})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "linkedin",
      "linked_in",
      "linked-in"
    ],
    "entropy": 2
  },
  {
    "id": "lob-api-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:lob)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}((live|test)_[a-f0-9]{35})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "test_",
      "live_"
    ]
  },
  {
    "id": "lob-pub-api-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:lob)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}((test|live)_pub_[a-f0-9]{31})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "test_pub",
      "live_pub",
      "_pub"
    ]
  },
  {
    "id": "looker-client-id",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:looker)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{20})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "looker"
    ]
  },
  {
    "id": "looker-client-secret",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:looker)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{24})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "looker"
    ]
  },
  {
    "id": "mailchimp-api-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:MailchimpSDK.initialize|mailchimp)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-f0-9]{32}-us\\d\\d)(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "mailchimp"
    ]
  },
  {
    "id": "mailgun-private-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:mailgun)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(key-[a-f0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "mailgun"
    ]
  },
  {
    "id": "mailgun-pub-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:mailgun)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(pubkey-[a-f0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "mailgun"
    ]
  },
  {
    "id": "mailgun-signing-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:mailgun)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "mailgun"
    ]
  },
  {
    "id": "mapbox-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:mapbox)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(pk\\.[a-z0-9]{60}\\.[a-z0-9]{22})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "mapbox"
    ]
  },
  {
    "id": "mattermost-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:mattermost)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{26})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "mattermost"
    ]
  },
  {
    "id": "maxmind-license-key",
    "regex": {
      "source": `\\b([A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk)(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "_mmk"
    ],
    "entropy": 4
  },
  {
    "id": "messagebird-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:message[_-]?bird)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{25})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "messagebird",
      "message-bird",
      "message_bird"
    ]
  },
  {
    "id": "messagebird-client-id",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:message[_-]?bird)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "messagebird",
      "message-bird",
      "message_bird"
    ]
  },
  {
    "id": "microsoft-teams-webhook",
    "regex": {
      "source": "https://[a-z0-9]+\\.webhook\\.office\\.com/webhookb2/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}@[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}/IncomingWebhook/[a-z0-9]{32}/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}",
      "flags": ""
    },
    "keywords": [
      "webhook.office.com",
      "webhookb2",
      "incomingwebhook"
    ]
  },
  {
    "id": "netlify-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:netlify)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9=_\\-]{40,46})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "netlify"
    ]
  },
  {
    "id": "new-relic-browser-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(NRJS-[a-f0-9]{19})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "nrjs-"
    ]
  },
  {
    "id": "new-relic-insert-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(NRII-[a-z0-9-]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "nrii-"
    ]
  },
  {
    "id": "new-relic-user-api-id",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "new-relic",
      "newrelic",
      "new_relic"
    ]
  },
  {
    "id": "new-relic-user-api-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(NRAK-[a-z0-9]{27})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "nrak"
    ]
  },
  {
    "id": "notion-api-token",
    "regex": {
      "source": `\\b(ntn_[0-9]{11}[A-Za-z0-9]{32}[A-Za-z0-9]{3})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "ntn_"
    ],
    "entropy": 4
  },
  {
    "id": "npm-access-token",
    "regex": {
      "source": `\\b(npm_[a-z0-9]{36})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "npm_"
    ],
    "entropy": 2
  },
  {
    "id": "nuget-config-password",
    "regex": {
      "source": '<add key=\\"(?:(?:ClearText)?Password)\\"\\s*value=\\"(.{8,})\\"\\s*/>',
      "flags": "i"
    },
    "keywords": [
      "<add key="
    ],
    "entropy": 1,
    "scopePath": {
      "source": "nuget\\.config$",
      "flags": "i"
    },
    "allowlists": [
      {
        "regexes": [
          {
            "source": "33f!!lloppa",
            "flags": ""
          },
          {
            "source": "hal\\+9ooo_da!sY",
            "flags": ""
          },
          {
            "source": "^\\%\\S.*\\%$",
            "flags": ""
          }
        ]
      }
    ]
  },
  {
    "id": "nytimes-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:nytimes|new-york-times,|newyorktimes)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9=_\\-]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "nytimes",
      "new-york-times",
      "newyorktimes"
    ]
  },
  {
    "id": "octopus-deploy-api-key",
    "regex": {
      "source": `\\b(API-[A-Z0-9]{26})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "api-"
    ],
    "entropy": 3
  },
  {
    "id": "okta-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:[\\w.-]{0,50}?(?:(?:[Oo]kta|OKTA))(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(00[\\w=\\-]{40})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "okta"
    ],
    "entropy": 4
  },
  {
    "id": "openai-api-key",
    "regex": {
      "source": `\\b(sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})\\b|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "t3blbkfj"
    ],
    "entropy": 3
  },
  {
    "id": "openshift-user-token",
    "regex": {
      "source": "\\b(sha256~[\\w-]{43})(?:[^\\w-]|$)",
      "flags": ""
    },
    "keywords": [
      "sha256~"
    ],
    "entropy": 3.5
  },
  {
    "id": "perplexity-api-key",
    "regex": {
      "source": `\\b(pplx-[a-zA-Z0-9]{48})(?:[\\x60'"\\s;]|\\\\[nr]|$|\\b)`,
      "flags": ""
    },
    "keywords": [
      "pplx-"
    ],
    "entropy": 4
  },
  {
    "id": "plaid-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:plaid)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(access-(?:sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "plaid"
    ]
  },
  {
    "id": "plaid-client-id",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:plaid)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{24})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "plaid"
    ],
    "entropy": 3.5
  },
  {
    "id": "plaid-secret-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:plaid)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{30})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "plaid"
    ],
    "entropy": 3.5
  },
  {
    "id": "planetscale-api-token",
    "regex": {
      "source": `\\b(pscale_tkn_[\\w=\\.-]{32,64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "pscale_tkn_"
    ],
    "entropy": 3
  },
  {
    "id": "planetscale-oauth-token",
    "regex": {
      "source": `\\b(pscale_oauth_[\\w=\\.-]{32,64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "pscale_oauth_"
    ],
    "entropy": 3
  },
  {
    "id": "planetscale-password",
    "regex": {
      "source": `\\b(pscale_pw_[\\w=\\.-]{32,64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "pscale_pw_"
    ],
    "entropy": 3
  },
  {
    "id": "postman-api-token",
    "regex": {
      "source": `\\b(PMAK-[a-f0-9]{24}\\-[a-f0-9]{34})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "pmak-"
    ],
    "entropy": 3
  },
  {
    "id": "prefect-api-token",
    "regex": {
      "source": `\\b(pnu_[a-zA-Z0-9]{36})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "pnu_"
    ],
    "entropy": 2
  },
  {
    "id": "private-key",
    "regex": {
      "source": "-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\\s\\S-]{64,}?KEY(?: BLOCK)?-----",
      "flags": "i"
    },
    "keywords": [
      "-----begin"
    ]
  },
  {
    "id": "privateai-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:[\\w.-]{0,50}?(?:private[_-]?ai)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "privateai",
      "private_ai",
      "private-ai"
    ],
    "entropy": 3
  },
  {
    "id": "pulumi-api-token",
    "regex": {
      "source": `\\b(pul-[a-f0-9]{40})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "pul-"
    ],
    "entropy": 2
  },
  {
    "id": "pypi-upload-token",
    "regex": {
      "source": "pypi-AgEIcHlwaS5vcmc[\\w-]{50,1000}",
      "flags": ""
    },
    "keywords": [
      "pypi-ageichlwas5vcmc"
    ],
    "entropy": 3
  },
  {
    "id": "rapidapi-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:rapidapi)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9_-]{50})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "rapidapi"
    ]
  },
  {
    "id": "readme-api-token",
    "regex": {
      "source": `\\b(rdme_[a-z0-9]{70})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "rdme_"
    ],
    "entropy": 2
  },
  {
    "id": "rubygems-api-token",
    "regex": {
      "source": `\\b(rubygems_[a-f0-9]{48})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "rubygems_"
    ],
    "entropy": 2
  },
  {
    "id": "scalingo-api-token",
    "regex": {
      "source": `\\b(tk-us-[\\w-]{48})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "tk-us-"
    ],
    "entropy": 2
  },
  {
    "id": "sendbird-access-id",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:sendbird)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "sendbird"
    ]
  },
  {
    "id": "sendbird-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:sendbird)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-f0-9]{40})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "sendbird"
    ]
  },
  {
    "id": "sendgrid-api-token",
    "regex": {
      "source": `\\b(SG\\.[a-z0-9=_\\-\\.]{66})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "sg."
    ],
    "entropy": 2
  },
  {
    "id": "sendinblue-api-token",
    "regex": {
      "source": `\\b(xkeysib-[a-f0-9]{64}\\-[a-z0-9]{16})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "xkeysib-"
    ],
    "entropy": 2
  },
  {
    "id": "sentry-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:sentry)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-f0-9]{64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "sentry"
    ],
    "entropy": 3
  },
  {
    "id": "sentry-org-token",
    "regex": {
      "source": "\\bsntrys_eyJpYXQiO[a-zA-Z0-9+/]{10,200}(?:LCJyZWdpb25fdXJs|InJlZ2lvbl91cmwi|cmVnaW9uX3VybCI6)[a-zA-Z0-9+/]{10,200}={0,2}_[a-zA-Z0-9+/]{43}(?:[^a-zA-Z0-9+/]|$)",
      "flags": ""
    },
    "keywords": [
      "sntrys_eyjpyxqio"
    ],
    "entropy": 4.5
  },
  {
    "id": "sentry-user-token",
    "regex": {
      "source": `\\b(sntryu_[a-f0-9]{64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "sntryu_"
    ],
    "entropy": 3.5
  },
  {
    "id": "settlemint-application-access-token",
    "regex": {
      "source": `\\b(sm_aat_[a-zA-Z0-9]{16})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "sm_aat"
    ],
    "entropy": 3
  },
  {
    "id": "settlemint-personal-access-token",
    "regex": {
      "source": `\\b(sm_pat_[a-zA-Z0-9]{16})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "sm_pat"
    ],
    "entropy": 3
  },
  {
    "id": "settlemint-service-access-token",
    "regex": {
      "source": `\\b(sm_sat_[a-zA-Z0-9]{16})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "sm_sat"
    ],
    "entropy": 3
  },
  {
    "id": "shippo-api-token",
    "regex": {
      "source": `\\b(shippo_(?:live|test)_[a-fA-F0-9]{40})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "shippo_"
    ],
    "entropy": 2
  },
  {
    "id": "shopify-access-token",
    "regex": {
      "source": "shpat_[a-fA-F0-9]{32}",
      "flags": ""
    },
    "keywords": [
      "shpat_"
    ],
    "entropy": 2
  },
  {
    "id": "shopify-custom-access-token",
    "regex": {
      "source": "shpca_[a-fA-F0-9]{32}",
      "flags": ""
    },
    "keywords": [
      "shpca_"
    ],
    "entropy": 2
  },
  {
    "id": "shopify-private-app-access-token",
    "regex": {
      "source": "shppa_[a-fA-F0-9]{32}",
      "flags": ""
    },
    "keywords": [
      "shppa_"
    ],
    "entropy": 2
  },
  {
    "id": "shopify-shared-secret",
    "regex": {
      "source": "shpss_[a-fA-F0-9]{32}",
      "flags": ""
    },
    "keywords": [
      "shpss_"
    ],
    "entropy": 2
  },
  {
    "id": "sidekiq-secret",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:BUNDLE_ENTERPRISE__CONTRIBSYS__COM|BUNDLE_GEMS__CONTRIBSYS__COM)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-f0-9]{8}:[a-f0-9]{8})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "bundle_enterprise__contribsys__com",
      "bundle_gems__contribsys__com"
    ]
  },
  {
    "id": "sidekiq-sensitive-url",
    "regex": {
      "source": "\\bhttps?://([a-f0-9]{8}:[a-f0-9]{8})@(?:gems.contribsys.com|enterprise.contribsys.com)(?:[\\/|\\#|\\?|:]|$)",
      "flags": "i"
    },
    "keywords": [
      "gems.contribsys.com",
      "enterprise.contribsys.com"
    ]
  },
  {
    "id": "slack-app-token",
    "regex": {
      "source": "xapp-\\d-[A-Z0-9]+-\\d+-[a-z0-9]+",
      "flags": "i"
    },
    "keywords": [
      "xapp"
    ],
    "entropy": 2
  },
  {
    "id": "slack-bot-token",
    "regex": {
      "source": "xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
      "flags": ""
    },
    "keywords": [
      "xoxb"
    ],
    "entropy": 3
  },
  {
    "id": "slack-config-access-token",
    "regex": {
      "source": "xoxe.xox[bp]-\\d-[A-Z0-9]{163,166}",
      "flags": "i"
    },
    "keywords": [
      "xoxe.xoxb-",
      "xoxe.xoxp-"
    ],
    "entropy": 2
  },
  {
    "id": "slack-config-refresh-token",
    "regex": {
      "source": "xoxe-\\d-[A-Z0-9]{146}",
      "flags": "i"
    },
    "keywords": [
      "xoxe-"
    ],
    "entropy": 2
  },
  {
    "id": "slack-legacy-bot-token",
    "regex": {
      "source": "xoxb-[0-9]{8,14}-[a-zA-Z0-9]{18,26}",
      "flags": ""
    },
    "keywords": [
      "xoxb"
    ],
    "entropy": 2
  },
  {
    "id": "slack-legacy-token",
    "regex": {
      "source": "xox[os]-\\d+-\\d+-\\d+-[a-fA-F\\d]+",
      "flags": ""
    },
    "keywords": [
      "xoxo",
      "xoxs"
    ],
    "entropy": 2
  },
  {
    "id": "slack-legacy-workspace-token",
    "regex": {
      "source": "xox[ar]-(?:\\d-)?[0-9a-zA-Z]{8,48}",
      "flags": ""
    },
    "keywords": [
      "xoxa",
      "xoxr"
    ],
    "entropy": 2
  },
  {
    "id": "slack-user-token",
    "regex": {
      "source": "xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}",
      "flags": ""
    },
    "keywords": [
      "xoxp-",
      "xoxe-"
    ],
    "entropy": 2
  },
  {
    "id": "slack-webhook-url",
    "regex": {
      "source": "(?:https?://)?hooks.slack.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}",
      "flags": ""
    },
    "keywords": [
      "hooks.slack.com"
    ]
  },
  {
    "id": "snyk-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:snyk[_.-]?(?:(?:api|oauth)[_.-]?)?(?:key|token))(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "snyk"
    ]
  },
  {
    "id": "sonar-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:sonar[_.-]?(login|token))(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}((?:squ_|sqp_|sqa_)?[a-z0-9=_\\-]{40})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "sonar"
    ],
    "secretGroup": 2
  },
  {
    "id": "sourcegraph-access-token",
    "regex": {
      "source": `\\b(\\b(sgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40}|sgp_[a-fA-F0-9]{40}|[a-fA-F0-9]{40})\\b)(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "sgp_",
      "sourcegraph"
    ],
    "entropy": 3
  },
  {
    "id": "square-access-token",
    "regex": {
      "source": `\\b((?:EAAA|sq0atp-)[\\w-]{22,60})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "sq0atp-",
      "eaaa"
    ],
    "entropy": 2
  },
  {
    "id": "squarespace-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:squarespace)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "squarespace"
    ]
  },
  {
    "id": "stripe-access-token",
    "regex": {
      "source": `\\b((?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "sk_test",
      "sk_live",
      "sk_prod",
      "rk_test",
      "rk_live",
      "rk_prod"
    ],
    "entropy": 2
  },
  {
    "id": "sumologic-access-id",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:[\\w.-]{0,50}?(?:(?:[Ss]umo|SUMO))(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(su[a-zA-Z0-9]{12})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "sumo"
    ],
    "entropy": 3
  },
  {
    "id": "sumologic-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:(?:[Ss]umo|SUMO))(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "sumo"
    ],
    "entropy": 3
  },
  {
    "id": "telegram-bot-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:telegr)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([0-9]{5,16}:(?:A)[a-z0-9_\\-]{34})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "telegr"
    ]
  },
  {
    "id": "travisci-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:travis)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{22})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "travis"
    ]
  },
  {
    "id": "twilio-api-key",
    "regex": {
      "source": "SK[0-9a-fA-F]{32}",
      "flags": ""
    },
    "keywords": [
      "sk"
    ],
    "entropy": 3
  },
  {
    "id": "twitch-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:twitch)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{30})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "twitch"
    ]
  },
  {
    "id": "twitter-access-secret",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:twitter)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{45})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "twitter"
    ]
  },
  {
    "id": "twitter-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:twitter)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([0-9]{15,25}-[a-zA-Z0-9]{20,40})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "twitter"
    ]
  },
  {
    "id": "twitter-api-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:twitter)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{25})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "twitter"
    ]
  },
  {
    "id": "twitter-api-secret",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:twitter)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{50})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "twitter"
    ]
  },
  {
    "id": "twitter-bearer-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:twitter)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(A{22}[a-zA-Z0-9%]{80,100})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "twitter"
    ]
  },
  {
    "id": "typeform-api-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:typeform)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(tfp_[a-z0-9\\-_\\.=]{59})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "tfp_"
    ]
  },
  {
    "id": "vault-batch-token",
    "regex": {
      "source": `\\b(hvb\\.[\\w-]{138,300})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": ""
    },
    "keywords": [
      "hvb."
    ],
    "entropy": 4
  },
  {
    "id": "vault-service-token",
    "regex": {
      "source": `\\b((?:hvs\\.[\\w-]{90,120}|s\\.(?:[a-z0-9]{24})))(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "hvs.",
      "s."
    ],
    "entropy": 3.5,
    "allowlists": [
      {
        "regexes": [
          {
            "source": "s\\.[A-Za-z]{24}",
            "flags": ""
          }
        ]
      }
    ]
  },
  {
    "id": "yandex-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:yandex)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(t1\\.[A-Z0-9a-z_-]+[=]{0,2}\\.[A-Z0-9a-z_-]{86}[=]{0,2})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "yandex"
    ]
  },
  {
    "id": "yandex-api-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:yandex)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(AQVN[A-Za-z0-9_\\-]{35,38})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "yandex"
    ]
  },
  {
    "id": "yandex-aws-access-token",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:yandex)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(YC[a-zA-Z0-9_\\-]{38})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "yandex"
    ]
  },
  {
    "id": "zendesk-secret-key",
    "regex": {
      "source": `[\\w.-]{0,50}?(?:zendesk)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{40})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      "flags": "i"
    },
    "keywords": [
      "zendesk"
    ]
  }
];
var GLOBAL_ALLOWLIST = {
  "paths": [
    "gitleaks\\.toml",
    "\\.(?:bmp|gif|jpe?g|png|svg|tiff?)$",
    "\\.(?:eot|[ot]tf|woff2?)$",
    "\\.(?:docx?|xlsx?|pdf|bin|socket|vsidx|v2|suo|wsuo|.dll|pdb|exe|gltf)$",
    "go\\.(?:mod|sum|work(?:\\.sum)?)$",
    "(?:^|/)vendor/modules\\.txt$",
    "(?:^|/)vendor/(?:github\\.com|golang\\.org/x|google\\.golang\\.org|gopkg\\.in|istio\\.io|k8s\\.io|sigs\\.k8s\\.io)(?:/.*)?$",
    "(?:^|/)gradlew(?:\\.bat)?$",
    "(?:^|/)gradle\\.lockfile$",
    "(?:^|/)mvnw(?:\\.cmd)?$",
    "(?:^|/)\\.mvn/wrapper/MavenWrapperDownloader\\.java$",
    "(?:^|/)node_modules(?:/.*)?$",
    "(?:^|/)(?:deno\\.lock|npm-shrinkwrap\\.json|package-lock\\.json|pnpm-lock\\.yaml|yarn\\.lock)$",
    "(?:^|/)bower_components(?:/.*)?$",
    "(?:^|/)(?:angular|bootstrap|jquery(?:-?ui)?|plotly|swagger-?ui)[a-zA-Z0-9.-]*(?:\\.min)?\\.js(?:\\.map)?$",
    "(?:^|/)javascript\\.json$",
    "(?:^|/)(?:Pipfile|poetry)\\.lock$",
    "(?:^|/)(?:v?env|virtualenv)/lib(?:64)?(?:/.*)?$",
    "(?:^|/)(?:lib(?:64)?/python[23](?:\\.\\d{1,2})+|python/[23](?:\\.\\d{1,2})+/lib(?:64)?)(?:/.*)?$",
    "(?:^|/)[a-z0-9_.]+-[0-9.]+\\.dist-info(?:/.+)?$",
    "(?:^|/)vendor/(?:bundle|ruby)(?:/.*?)?$",
    "\\.gem$",
    "verification-metadata\\.xml",
    "Database.refactorlog",
    "(?:^|/)\\.git$"
  ],
  "regexes": [
    {
      "source": "^true|false|null$",
      "flags": "i"
    },
    {
      "source": "^(?:a+|b+|c+|d+|e+|f+|g+|h+|i+|j+|k+|l+|m+|n+|o+|p+|q+|r+|s+|t+|u+|v+|w+|x+|y+|z+|\\*+|\\.+)$",
      "flags": "i"
    },
    {
      "source": "^\\$(?:\\d+|{\\d+})$",
      "flags": ""
    },
    {
      "source": "^\\$(?:[A-Z_]+|[a-z_]+)$",
      "flags": ""
    },
    {
      "source": "^\\${(?:[A-Z_]+|[a-z_]+)}$",
      "flags": ""
    },
    {
      "source": "^\\{\\{[ \\t]*[\\w ().|]+[ \\t]*}}$",
      "flags": ""
    },
    {
      "source": `^\\$\\{\\{[ \\t]*(?:(?:env|github|secrets|vars)(?:\\.[A-Za-z]\\w+)+[\\w "'&./=|]*)[ \\t]*}}$`,
      "flags": ""
    },
    {
      "source": "^%(?:[A-Z_]+|[a-z_]+)%$",
      "flags": ""
    },
    {
      "source": "^%[+\\-# 0]?[bcdeEfFgGoOpqstTUvxX]$",
      "flags": ""
    },
    {
      "source": "^\\{\\d{0,2}}$",
      "flags": ""
    },
    {
      "source": "^@(?:[A-Z_]+|[a-z_]+)@$",
      "flags": ""
    },
    {
      "source": "^/Users/[a-z0-9]+/[\\w .-/]+$",
      "flags": "i"
    },
    {
      "source": "^/(?:bin|etc|home|opt|tmp|usr|var)/[\\w ./-]+$",
      "flags": ""
    }
  ],
  "stopwords": [
    "014df517-39d1-4453-b7b3-9930c563627c",
    "abcdefghijklmnopqrstuvwxyz"
  ]
};

// src/engine/scanner.ts
var ScanBudgetError = class extends Error {
  constructor(ms) {
    super(`scan exceeded its ${ms}ms budget`);
    this.name = "ScanBudgetError";
  }
};
var PLACEHOLDER_ONLY = /^SECRETGATE_[0-9a-f]{12,16}$/;
function compileAllowlist(a) {
  return {
    condition: a.condition === "AND" ? "AND" : "OR",
    regexTarget: a.regexTarget ?? "secret",
    regexes: (a.regexes ?? []).map((r) => new RegExp(r.source, r.flags)),
    stopwords: a.stopwords ?? [],
    paths: (a.paths ?? []).map((r) => new RegExp(r.source, r.flags))
  };
}
var IIN = /^(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|2(?:22[1-9]|2[3-9]\d|[3-6]\d{2}|7[01]\d|720)\d{12}|3[47]\d{13}|6(?:011|5\d{2})\d{12})$/;
var PLACEHOLDER_WORDS = /* @__PURE__ */ new Set([
  "password",
  "passwd",
  "pass",
  "secret",
  "changeme",
  "change-me",
  "example",
  "examplepassword",
  "test",
  "testpassword",
  "token",
  "your_password",
  "yourpassword",
  "admin",
  "root",
  "user",
  "username",
  "guest",
  "none",
  "null",
  "redacted",
  "hunter2",
  "placeholder"
]);
function unquote(v) {
  const first = v[0];
  if ((first === '"' || first === "'" || first === "`") && v.length >= 2 && v[v.length - 1] === first) {
    return v.slice(1, -1);
  }
  return v;
}
function looksLikeInterpolation(v) {
  return /^\$\{[^{}]*\}$/.test(v) || // ${VAR}, ${this.key}, ${env:DB_PASSWORD}
  /^\$\([^()]*\)$/.test(v) || // $(cat /run/secrets/db)
  /^#\{.*\}$/.test(v) || // Ruby / CoffeeScript #{...}
  /^\{\{.*\}\}$/.test(v) || // Jinja / Go / Handlebars {{ ... }}
  /^\{[A-Za-z_][\w.]*\}$/.test(v) || // Python str.format {settings.api_key}
  /^%\([A-Za-z_]\w*\)[a-z]$/.test(v) || // printf mapping %(db_password)s
  /^<%=?[\s\S]*%>$/.test(v);
}
function looksLikePlaceholder(raw) {
  const v = unquote(raw);
  const low = v.toLowerCase();
  if (PLACEHOLDER_WORDS.has(low)) return true;
  if (/^[*x•.\-_]+$/.test(v)) return true;
  if (/^\$\{?[a-z_][\w]*\}?$/i.test(v)) return true;
  if (looksLikeInterpolation(v.trim())) return true;
  if (/^%[a-z_]+%$/i.test(v)) return true;
  if (/^<[^>]+>$/.test(v)) return true;
  if (/^[a-z]+$/.test(low) && new Set(low).size <= 3) return true;
  return false;
}
function looksLikeFilesystemPath(raw) {
  const v = unquote(raw);
  if (!/^(?:\/|\.\.?\/|~\/|[A-Za-z]:[\\/])/.test(v)) return false;
  const separators = (v.match(/[\\/]/g) ?? []).length;
  if (separators < 2) return false;
  return /^[A-Za-z0-9._\-\\/: ]+$/.test(v);
}
var BUILTIN_RULES = [
  {
    id: "credit-card-number",
    // The lookarounds exclude a DECIMAL context, not just an adjacent digit. On
    // a 42k-file corpus, 231 of 250 card findings were SVG path/ellipse
    // coordinates and the rest geo fixtures: a long fraction satisfies Luhn
    // roughly one time in ten, and vector art emits thousands of them. A PAN is
    // never written immediately after a decimal point, nor immediately before
    // one followed by digits.
    re: /(?<![\d.-])(\d(?:[ -]?\d){12,18})(?![\d-])(?!\.\d)/dg,
    keywords: [],
    allowlists: [],
    post: (secret) => {
      const digits = secret.replace(/[ -]/g, "");
      return IIN.test(digits) && luhnValid(digits);
    }
  },
  // Credentials embedded in a URL / connection string: scheme://[user]:PASSWORD@host
  // (postgres, mysql, mongodb+srv, redis, amqp, https basic-auth, …). gitleaks
  // ships no generic rule for this and it is an extremely common leak. The
  // captured group is the PASSWORD; a placeholder-ish value is skipped.
  {
    id: "url-credentials",
    // The scheme is bounded and anchored on a non-scheme character: `\b` fired
    // after every `.`/`-`, making `x://a.a.a.…` quadratic (6 s on 160 KB), and
    // the scan deadline is only checked between rules.
    re: /(?<![a-z0-9+.-])[a-z][a-z0-9+.-]{0,31}:\/\/[^\s:/@]{0,256}:([^\s:/@]{3,256})@[^\s]+/dgi,
    keywords: ["://"],
    allowlists: [],
    post: (secret) => !looksLikePlaceholder(secret),
    // The username and the scheme are only knowable from the whole match, so
    // this gate can't live in `post`. 44 of 196 URL-credential findings on the
    // corpus repeated one or the other — the canonical docker-compose and
    // tutorial string, where the password IS `postgres`, `root` or `mongodb`.
    // EQUALITY, never containment: a password that merely BEGINS with the
    // username still fires. (Spelling that counter-example out as a real URL
    // here would trip the repo's own self-scan, which reads this comment.)
    postMatch: (secret, match) => {
      const m = /^([a-z][a-z0-9+.-]*):\/\/([^\s:/@]*):/i.exec(match);
      if (!m) return true;
      const low = secret.toLowerCase();
      const scheme = m[1].toLowerCase().split("+")[0];
      return low !== m[2].toLowerCase() && low !== scheme;
    }
  },
  // QUOTED password / secret assignment with a BROADER value charset than
  // gitleaks' generic-api-key (which stops at `[\w.=-]`, missing `$!@#…`).
  // Quoted-only on purpose: an unquoted value can't be told apart from ordinary
  // code (`secret === undefined`, `apiKey = getKey()`), which floods false
  // positives — quoted values after a secret keyword are almost always literals.
  // Entropy-gated and placeholder-filtered.
  {
    id: "password-assignment",
    re: /(?:password|passwd|pwd|secret|access[_-]?key|api[_-]?key|auth[_-]?token)["']?\s*(?:[:=]|:=|=>)\s*(?:"([^"\n]{6,200})"|'([^'\n]{6,200})'|`([^`\n]{6,200})`)/dgi,
    keywords: ["password", "passwd", "pwd", "secret", "key", "token"],
    entropy: 3,
    allowlists: [],
    // Whitespace disqualifies the value. gitleaks' generic-api-key stops at
    // `[\w.=-]`, so upstream never matches a spaced value at all; this rule
    // widened the charset to catch punctuation-heavy passwords, and that
    // widening is exactly what let prose in. 155 of 649 findings on the corpus
    // held a space, and every sampled one was a UI label or a sentence
    // (`"password": "Client Secret"` in Airflow's connection-form metadata).
    // The cost is a spaced passphrase, which this rule now leaves to a real
    // password manager — the same trade-off the README already states.
    post: (secret) => !/\s/.test(secret) && !looksLikePlaceholder(secret) && !looksLikeFilesystemPath(secret) && !/^SECRETGATE_[0-9a-f]{12,16}$/.test(secret)
  }
];
var COMPILED = [
  ...RULES.map((r) => ({
    id: r.id,
    re: new RegExp(r.regex.source, r.regex.flags.includes("g") ? r.regex.flags + "d" : r.regex.flags + "dg"),
    entropy: r.entropy,
    secretGroup: r.secretGroup,
    keywords: r.keywords,
    allowlists: (r.allowlists ?? []).map(compileAllowlist),
    scope: r.scopePath ? new RegExp(r.scopePath.source, r.scopePath.flags) : void 0
  })),
  ...BUILTIN_RULES
];
var RULE_SOURCE_TEXTS;
function isRuleSourceText(secret) {
  RULE_SOURCE_TEXTS ??= COMPILED.flatMap((r) => [r.re.source, JSON.stringify(r.re.source).slice(1, -1)]);
  return RULE_SOURCE_TEXTS.some((s) => s.includes(secret));
}
var GLOBAL_PATHS = GLOBAL_ALLOWLIST.paths.map((p) => new RegExp(p));
var GLOBAL_REGEXES = GLOBAL_ALLOWLIST.regexes.map((r) => new RegExp(r.source, r.flags));
var GLOBAL_STOPWORDS = GLOBAL_ALLOWLIST.stopwords;
function lineStarts(text) {
  const starts = [0];
  for (let i = 0; i < text.length; i++) {
    if (text[i] === "\n") starts.push(i + 1);
  }
  return starts;
}
function lineAt(starts, offset) {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = lo + hi + 1 >> 1;
    if (starts[mid] <= offset) lo = mid;
    else hi = mid - 1;
  }
  return lo;
}
function lineText(text, starts, line) {
  const start = starts[line];
  const end = line + 1 < starts.length ? starts[line + 1] - 1 : text.length;
  return text.slice(start, end);
}
function allowlistMatches(a, secret, target, sourcePath) {
  const checks = [];
  if (a.regexes.length > 0) checks.push(a.regexes.some((re) => re.test(target)));
  if (a.stopwords.length > 0) {
    const lowerSecret = secret.toLowerCase();
    checks.push(a.stopwords.some((s) => lowerSecret.includes(s)));
  }
  if (a.paths.length > 0) checks.push(sourcePath !== void 0 && a.paths.some((re) => re.test(sourcePath)));
  if (checks.length === 0) return false;
  return a.condition === "AND" ? checks.every(Boolean) : checks.some(Boolean);
}
function pickSecret(match, secretGroup) {
  const indices = match.indices;
  if (secretGroup && secretGroup > 0 && match[secretGroup] !== void 0) {
    const [s2, e2] = indices[secretGroup];
    return { secret: match[secretGroup], start: s2, end: e2 };
  }
  for (let g = 1; g < match.length; g++) {
    if (match[g] !== void 0 && match[g].length > 0) {
      const [s2, e2] = indices[g];
      return { secret: match[g], start: s2, end: e2 };
    }
  }
  const [s, e] = indices[0];
  return { secret: match[0], start: s, end: e };
}
function scan(text, cfg = {}) {
  if (text.length === 0) return [];
  if (cfg.sourcePath) {
    if (GLOBAL_PATHS.some((re) => re.test(cfg.sourcePath))) return [];
    if (isAllowedPath(cfg.sourcePath, cfg.allowlist)) return [];
  }
  const lower = text.toLowerCase();
  const starts = lineStarts(text);
  const pragmaLines = cfg.pragmas === false ? /* @__PURE__ */ new Set() : pragmaAllowedLines(text);
  const findings = [];
  const deadline = cfg.deadlineMs !== void 0 ? performance.now() + cfg.deadlineMs : Number.POSITIVE_INFINITY;
  for (const rule of COMPILED) {
    if (performance.now() > deadline) throw new ScanBudgetError(cfg.deadlineMs);
    if (isDisabledRule(rule.id, cfg.allowlist)) continue;
    if (rule.scope && cfg.sourcePath && !rule.scope.test(cfg.sourcePath)) continue;
    if (rule.keywords.length > 0 && !rule.keywords.some((k) => lower.includes(k))) continue;
    rule.re.lastIndex = 0;
    for (const match of text.matchAll(rule.re)) {
      const { secret, start, end } = pickSecret(match, rule.secretGroup);
      if (secret.length === 0) continue;
      if (PLACEHOLDER_ONLY.test(secret)) continue;
      if (isRuleSourceText(secret)) continue;
      if (looksLikePlaceholder(secret)) continue;
      if (rule.post && !rule.post(secret)) continue;
      if (rule.postMatch && !rule.postMatch(secret, match[0])) continue;
      const entropy = shannonEntropy(secret);
      if (rule.entropy !== void 0 && entropy <= rule.entropy) continue;
      const line = lineAt(starts, start);
      if (pragmaLines.has(line)) continue;
      const fullMatch = match[0];
      let allowed = false;
      for (const a of rule.allowlists) {
        const target = a.regexTarget === "match" ? fullMatch : a.regexTarget === "line" ? lineText(text, starts, line) : secret;
        if (allowlistMatches(a, secret, target, cfg.sourcePath)) {
          allowed = true;
          break;
        }
      }
      if (allowed) continue;
      if (GLOBAL_REGEXES.length > 0 && GLOBAL_REGEXES.some((re) => re.test(secret))) continue;
      if (GLOBAL_STOPWORDS.length > 0 && GLOBAL_STOPWORDS.some((s) => secret.toLowerCase().includes(s))) continue;
      if (isAllowedValue(secret, cfg.allowlist)) continue;
      findings.push({ ruleId: rule.id, match: fullMatch, secret, start, end, entropy, line });
    }
  }
  return dedupe(findings);
}
function dedupe(findings) {
  const sorted = [...findings].sort((a, b) => a.start - b.start || b.end - a.end);
  const kept = [];
  for (const f of sorted) {
    const clash = kept.findIndex((k) => f.start < k.end && k.start < f.end);
    if (clash === -1) {
      kept.push(f);
      continue;
    }
    const other = kept[clash];
    const fGeneric = f.ruleId === "generic-api-key";
    const oGeneric = other.ruleId === "generic-api-key";
    const preferF = oGeneric && !fGeneric || fGeneric === oGeneric && f.end - f.start > other.end - other.start;
    if (preferF) kept[clash] = f;
  }
  return kept.sort((a, b) => a.start - b.start);
}

// src/redact.ts
function redactText(text, vault, source, cfg = {}) {
  const findings = scan(text, { ...cfg, pragmas: cfg.pragmas ?? false });
  if (findings.length === 0) return { text, findings, replaced: [] };
  let out = text;
  const replaced = [];
  for (const f of [...findings].sort((a, b) => b.start - a.start)) {
    const placeholder = vault.recordSecret(f.secret, f.ruleId, source);
    out = out.slice(0, f.start) + placeholder + out.slice(f.end);
    replaced.push({ placeholder, ruleId: f.ruleId });
  }
  replaced.reverse();
  return { text: out, findings, replaced };
}
function restorePlaceholders(text, vault) {
  let restored = 0;
  const out = text.replace(PLACEHOLDER_RE, (placeholder) => {
    const secret = vault.secretFor(placeholder);
    if (secret === void 0) return placeholder;
    restored++;
    return secret;
  });
  return { text: out, restored };
}

// src/hooks/scan-budget.ts
var SCAN_CAP = 2 * 1024 * 1024;
var SCAN_DEADLINE_MS = 5e3;
function isBinaryField(key, value, parent) {
  return key === "data" && ["image", "audio"].includes(parent.type ?? "") || key === "base64" && ["image", "audio"].includes(parent.type ?? "") && typeof value === "string" && /^[A-Za-z0-9+/=\s]*$/.test(value) || key === "url" && typeof value === "string" && /^data:(image|audio)\//.test(value);
}
function eventRedactor(vault, source, allowlist) {
  const deadline = performance.now() + SCAN_DEADLINE_MS;
  let remaining = SCAN_CAP;
  return (text) => {
    remaining -= text.length;
    const deadlineMs = deadline - performance.now();
    if (remaining < 0 || deadlineMs <= 0) throw new Error("scan budget exceeded");
    return redactText(text, vault, source, { allowlist, deadlineMs }).text;
  };
}

// src/hooks/tool-call.ts
var SHELL = /* @__PURE__ */ new Set(["bash", "shell", "exec", "exec_command", "local_shell", "localshell", "run_command", "container.exec", "unified_exec"]);
var READ = /* @__PURE__ */ new Set(["read", "read_file", "view", "open_file", "notebookread", "cat"]);
var WRITE = /* @__PURE__ */ new Set(["write", "write_file", "create_file", "edit", "multiedit", "notebookedit", "str_replace", "str_replace_editor", "edit_file"]);
var PATCH = /* @__PURE__ */ new Set(["apply_patch", "patch"]);
var LIST = /* @__PURE__ */ new Set(["ls", "list", "list_dir", "list_directory"]);
var SEARCH_GLOB = /* @__PURE__ */ new Set(["glob", "find_files", "file_search"]);
var SEARCH_GREP = /* @__PURE__ */ new Set(["grep", "search", "search_files", "codesearch"]);
var str = (v) => typeof v === "string" && v.length > 0 ? v : void 0;
function patchPaths(patch) {
  const out = [];
  for (const m of patch.matchAll(/^\*\*\* (?:Add File|Update File|Delete File|Move to): *(.+?) *$/gm)) out.push(m[1]);
  return out;
}
function filePaths(input) {
  const out = [];
  for (const key of [
    "file_path",
    "filePath",
    "path",
    "notebook_path",
    "notebookPath",
    "target_file",
    "file",
    "source",
    "destination",
    "src",
    "dest",
    "from",
    "to",
    "sourcePath",
    "destinationPath",
    "old_path",
    "new_path"
  ]) {
    const v = str(input[key]);
    if (v) out.push(v);
  }
  for (const key of ["paths", "file_paths", "filePaths"]) {
    if (Array.isArray(input[key])) {
      for (const v of input[key]) if (str(v)) out.push(v);
    }
  }
  if (Array.isArray(input.edits)) {
    for (const e of input.edits) if (e && typeof e === "object" && str(e.file_path ?? e.filePath)) out.push(e.file_path ?? e.filePath);
  }
  return [...new Set(out)];
}
function patchText(input) {
  for (const key of ["patchText", "patch", "input", "command", "diff"]) {
    const v = input[key];
    if (typeof v === "string" && v.includes("*** ")) return v;
  }
  return void 0;
}
function extractToolCall(toolName, toolInput) {
  const name = toolName.toLowerCase().replace(/^functions\./, "").replace(/^mcp__.*__/, "");
  if (typeof toolInput === "string") {
    if (PATCH.has(name) || toolInput.startsWith("*** Begin Patch")) return { kind: "patch", paths: patchPaths(toolInput) };
    if (SHELL.has(name)) return { kind: "shell", paths: [], command: toolInput };
    return { kind: "other", paths: [] };
  }
  const input = toolInput && typeof toolInput === "object" ? toolInput : {};
  if (PATCH.has(name)) {
    const patch = patchText(input);
    return { kind: "patch", paths: patch ? patchPaths(patch) : filePaths(input) };
  }
  if (SHELL.has(name)) {
    const cmd = input.cmd ?? input.command;
    if (typeof cmd === "string" && /^\s*apply_patch\b/.test(cmd)) return { kind: "patch", paths: patchPaths(cmd) };
    if (Array.isArray(cmd) && cmd[0] === "apply_patch" && typeof cmd[1] === "string") return { kind: "patch", paths: patchPaths(cmd[1]) };
    const command = typeof cmd === "string" ? cmd : Array.isArray(cmd) ? cmd.map(String) : void 0;
    return { kind: "shell", paths: [], command, workdir: str(input.workdir) ?? str(input.cwd) };
  }
  if (READ.has(name)) return { kind: "read", paths: filePaths(input) };
  if (WRITE.has(name)) return { kind: "write", paths: filePaths(input) };
  if (LIST.has(name)) return { kind: "list", paths: filePaths(input) };
  if (SEARCH_GLOB.has(name) || SEARCH_GREP.has(name)) {
    const root = str(input.path) ?? str(input.directory) ?? str(input.dir);
    const pattern = SEARCH_GLOB.has(name) ? str(input.pattern) ?? str(input.glob) : str(input.glob) ?? str(input.include);
    return { kind: "search", paths: root ? [root] : [], searchRoot: root, pattern, content: SEARCH_GREP.has(name) };
  }
  return { kind: "other", paths: filePaths(input) };
}

// src/prompt-directive.ts
var NAME = String.raw`[\`'"]?secretgate[\`'"]?`;
var COURTESY = String.raw`(?:(?:stp|svp|please|pls|merci|thanks|now|maintenant|ok|okay)[\s,.!]*)*`;
var TAIL = String.raw`(?:\s+(?:pour|for)\s+(?:cette|ce|this|la|the)\s+(?:session|run|conversation|conv))?(?:\s+(?:stp|svp|please|merci|thanks))?\s*[.!]*`;
var SCOPE = String.raw`(?:\s+(?:et|and|\+|avec|with|,)\s*(?:le|la|the)?\s*(?:scope|p[ée]rim[èe]tre))?`;
var DISABLE = new RegExp(
  String.raw`^${COURTESY}(?:d[ée]sactiv(?:e|er|ez)|coupe(?:r|z)?|mets\s+en\s+pause|disable|turn\s+off|switch\s+off|pause)\s+(?:le\s+|la\s+|the\s+)?${NAME}(${SCOPE})${TAIL}$|^${COURTESY}(?:turn\s+|switch\s+)?${NAME}\s*:?\s*off${TAIL}$`,
  "i"
);
var ENABLE = new RegExp(
  String.raw`^${COURTESY}(?:r[ée]activ(?:e|er|ez)|rallume(?:r|z)?|enable|re-?enable|turn\s+(?:back\s+)?on|resume)\s+(?:le\s+|la\s+|the\s+)?${NAME}(?:\s+back\s+on)?${TAIL}$|^${COURTESY}(?:turn\s+|switch\s+)?${NAME}\s*:?\s*(?:back\s+)?on${TAIL}$`,
  "i"
);
var SKILL_DISABLE = /^[/$]secretgate\s+(?:disable|off|pause|stop|d[ée]sactiv(?:e|er|ez)?|coupe)(\s+(?:--)?(?:scope|p[ée]rim[èe]tre)|\s+(?:et|and|\+)\s+(?:le\s+|la\s+|the\s+)?(?:scope|p[ée]rim[èe]tre))?\s*[.!]*$/i;
var SKILL_ENABLE = /^[/$]secretgate\s+(?:enable|on|resume|r[ée]activ(?:e|er|ez)?|rallume)\s*[.!]*$/i;
function promptDirective(prompt) {
  for (const raw of prompt.split(/\r?\n/)) {
    const line = raw.trim().replace(/^(["'`])(.*)\1$/, "$2").trim();
    if (line.length === 0 || line.length > 120) continue;
    const skillOff = SKILL_DISABLE.exec(line);
    if (skillOff) return { action: "disable", liftScope: Boolean(skillOff[1]) };
    if (SKILL_ENABLE.test(line)) return { action: "enable" };
    const off = DISABLE.exec(line);
    if (off) return { action: "disable", liftScope: Boolean(off[1]) };
    if (ENABLE.test(line)) return { action: "enable" };
  }
  return void 0;
}
function applyPromptDirective(directive, sessionId, cwd) {
  if (!sessionId) {
    return "secretgate: this agent did not report a session id, so it cannot be paused from the conversation \u2014 run `secretgate disable --session` in a terminal instead.";
  }
  if (directive.action === "enable") {
    const cleared = removePause("session", sessionId);
    const still = disableState({ sessionId, cwd });
    if (still.disabled) {
      const how = still.scope === "env" ? "unset SECRETGATE_DISABLE and restart the agent" : "run `secretgate enable` in a terminal";
      return `secretgate: ${cleared.length > 0 ? "this session's pause is cleared, but " : ""}secretgate is still DISABLED here \u2014 ${describeDisable(still)}. That pause is not the session's own: ${how}.`;
    }
    return cleared.length > 0 ? "secretgate: re-enabled for this session, at your request. Prompts, tool input and tool output are scanned again." : "secretgate: already active for this session.";
  }
  addPause({ scope: "session", target: sessionId, minutes: null, cwd, lifetime: true, liftScope: directive.liftScope });
  return [
    "secretgate: DISABLED for this session only, at your request \u2014 prompts, tool input and tool output are no longer scanned until the session ends (24 h at most).",
    directive.liftScope ? "The project scope is lifted too." : "A project scope, if any, stays enforced (say \u201Cd\xE9sactive secretgate et le scope\u201D to lift it too).",
    "Say \u201Cr\xE9active secretgate\u201D to turn it back on. A new session is protected automatically."
  ].join(" ");
}

// src/adapters/opencode-plugin.ts
var ALLOW_TAG = "[allow-secret]";
function mutateStringsInPlace(container, fn) {
  if (container === null || typeof container !== "object") return false;
  const pending = [];
  const stack = [container];
  const seen = /* @__PURE__ */ new Set();
  while (stack.length) {
    const current = stack.pop();
    if (seen.has(current)) continue;
    seen.add(current);
    for (const key of Object.keys(current)) {
      const value = current[key];
      if (isBinaryField(key, value, current)) continue;
      const mappedKey = fn(key);
      const mapped = typeof value === "string" ? fn(value) : value;
      if (mapped !== value || mappedKey !== key)
        pending.push(() => {
          if (mappedKey !== key) delete current[key];
          Object.defineProperty(current, mappedKey, { value: mapped, enumerable: true, configurable: true, writable: true });
        });
      if (value !== null && typeof value === "object") stack.push(value);
    }
  }
  for (const apply of pending) apply();
  return pending.length > 0;
}
var RESTORE_TOOLS = /* @__PURE__ */ new Set(["write", "edit", "patch", "apply_patch", "multiedit"]);
function attachedPath(part) {
  if (typeof part.url === "string" && part.url.startsWith("file:")) {
    try {
      return fileURLToPath(part.url);
    } catch {
      return void 0;
    }
  }
  if (typeof part.source?.path === "string") return part.source.path;
  if (part.synthetic && typeof part.text === "string") return /"filePath":\s*"((?:[^"\\]|\\.)*)"/.exec(part.text)?.[1];
  return void 0;
}
var SecretgatePlugin = async (ctx) => {
  const directory = ctx?.directory;
  const cwd = typeof directory === "string" ? directory : process.cwd();
  const offState = (sessionId) => disableState({ cwd, sessionId: typeof sessionId === "string" ? sessionId : void 0 });
  const isOff = (sessionId) => offState(sessionId).disabled;
  const client = ctx?.client;
  const isSubsession = async (sessionId) => {
    if (typeof sessionId !== "string") return false;
    if (typeof client?.session?.get !== "function") return true;
    try {
      const res = await client.session.get({ path: { id: sessionId } });
      return typeof res?.data?.parentID === "string" && res.data.parentID.length > 0;
    } catch {
      return true;
    }
  };
  const configFor = (sessionId) => {
    const cfg = loadConfig(cwd);
    return offState(sessionId).includesScope ? { ...cfg, scopes: [], error: void 0 } : cfg;
  };
  return {
    // OpenCode keeps rewritten args in tool history, including failed calls.
    // Redact that history immediately before it is converted to model messages.
    "experimental.chat.messages.transform": async (_input, output) => {
      for (const message of output.messages ?? []) {
        if (isOff(message.info?.sessionID)) continue;
        try {
          const cfg = loadConfig(cwd);
          const vault = new Vault();
          for (const part of message.parts ?? []) {
            if (part?.type === "tool") mutateStringsInPlace(part, eventRedactor(vault, "opencode:history", cfg.allowlist));
          }
        } catch {
          throw new Error("secretgate: tool history could not be scanned safely; start a fresh session.");
        }
      }
    },
    "chat.message": async (input, output) => {
      const sessionID = input?.sessionID;
      recordSession(typeof sessionID === "string" ? sessionID : void 0, cwd);
      const parts = output?.parts;
      if (!Array.isArray(parts)) return;
      const said = parts.find(
        (p) => typeof p?.text === "string" && !p.synthetic && (p.type === void 0 || p.type === "text") && promptDirective(String(p.text))
      );
      if (said && await isSubsession(sessionID)) {
        said.text = `${said.text}

[secretgate: ignored an off-switch \u2014 this session could not be confirmed as your main session (a subagent prompt is written by the model). Run \`secretgate disable --session\` in a terminal instead]`;
      } else if (said) {
        const notice = applyPromptDirective(promptDirective(String(said.text)), typeof sessionID === "string" ? sessionID : void 0, cwd);
        said.text = `${said.text}

[${notice}]`;
      }
      const cfg = configFor(sessionID);
      if (cfg.scopes.length > 0) {
        for (const part of parts) {
          if (!part || typeof part !== "object") continue;
          const path = attachedPath(part);
          const why = path ? cfg.scopes.map((s) => accessViolation(s, path, cwd, "read")).find(Boolean) : void 0;
          if (why) {
            for (const key of ["url", "filename", "mime", "source"]) delete part[key];
            part.type = "text";
            part.text = `[secretgate: an attachment was removed \u2014 ${why}]`;
            continue;
          }
          if (typeof part.text === "string" && !part.synthetic) {
            const mention = promptScopeViolation(cfg.scopes, part.text, cwd);
            if (mention) throw new Error(mention);
          }
        }
      }
      if (isOff(sessionID)) return;
      for (const part of parts) {
        const path = part && typeof part === "object" && part.type === "file" ? attachedPath(part) : void 0;
        if (path && sensitivePathMatch(path, cfg.allowlist, cwd)) {
          for (const key of ["url", "filename", "mime", "source"]) delete part[key];
          part.type = "text";
          part.text = `[secretgate: an attachment was removed \u2014 '${path}' looks sensitive; reference its values as env vars instead]`;
        }
      }
      const typed = (p) => typeof p?.text === "string" && !p.synthetic && (p.type === void 0 || p.type === "text");
      const bypass = parts.some((p) => typed(p) && String(p.text).includes(ALLOW_TAG));
      try {
        const vault = new Vault();
        const redact = eventRedactor(vault, "opencode:prompt", cfg.allowlist);
        const mapped = parts.map((part) => typeof part?.text === "string" && !(bypass && typed(part)) ? redact(part.text) : void 0);
        parts.forEach((part, i) => {
          if (mapped[i] !== void 0) part.text = mapped[i];
        });
      } catch {
        throw new Error("secretgate: prompt could not be scanned safely; shorten it and retry.");
      }
    },
    "tool.execute.before": async (input, output) => {
      const tool = String(input?.tool ?? "").toLowerCase();
      const args = output?.args ?? {};
      const cfg = configFor(input?.sessionID);
      const decision = preToolPolicy(extractToolCall(tool, args), cfg, cwd, { disabled: isOff(input?.sessionID) });
      if (decision) {
        throw new Error(
          decision.action === "ask" ? `${decision.reason} OpenCode plugins cannot ask for approval, so this was refused: run it yourself if you meant it.` : decision.reason
        );
      }
      const restoreThis = RESTORE_TOOLS.has(tool) || tool === "bash" && cfg.restoreBash;
      if (restoreThis) {
        const vault = new Vault();
        mutateStringsInPlace(args, (s) => restorePlaceholders(s, vault).text);
      }
    },
    "tool.execute.after": async (input, output) => {
      const tool = String(input?.tool ?? "").toLowerCase();
      try {
        const cfg = configFor(input?.sessionID);
        const kind = extractToolCall(tool, input?.args).kind;
        if (cfg.scopes.length > 0 && (kind === "search" || kind === "list") && typeof output?.output === "string") {
          output.output = filterSearchOutput(cfg.scopes, output.output, cwd).value;
        }
        if (isOff(input?.sessionID)) return;
        const vault = new Vault();
        mutateStringsInPlace(output, eventRedactor(vault, `opencode:${tool}`, cfg.allowlist));
      } catch {
        const notice = "[secretgate withheld this tool output: scan failed or output exceeded the scan budget]";
        if (!output || typeof output !== "object") throw new Error(notice);
        const mcp = "content" in output;
        for (const key of Object.keys(output)) delete output[key];
        if (mcp) {
          output.content = [{ type: "text", text: notice }];
          output.isError = true;
        } else {
          output.output = notice;
          output.title = "secretgate: output withheld";
          output.metadata = {};
        }
      }
    }
  };
};
export {
  SecretgatePlugin
};

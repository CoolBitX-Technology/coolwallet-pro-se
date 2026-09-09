package coolbitx;

import javacard.framework.ISOException;

public class RlpDataParser {

	// dataOffset/dataLength always describe CONTENT only — the resolved
	// element's own RLP header (prefix + length bytes) is never included,
	// for both string/object results and list/array results. A caller that
	// needs to navigate further into a list result should use
	// decodeChildByIndex(), not feed dataOffset/dataLength back into
	// execute()/decodeByIndex() (those expect a value with its own header).
	private static short dataOffset;
	private static short dataLength;

	private static byte[] path = new byte[1];
	private static final short pathOffset = Common.OFFSET_ZERO;

	public static short getDataOffset() {
		return dataOffset;
	}

	public static short getDataLength() {
		return dataLength;
	}

	public static void execute(byte[] rlpList, short rlpListOffset, short rlpListLength,
			byte[] rlpPath, short rlpPathOffset, short rlpPathLength) {
		// Current index in the RLP list
		short listIndex = rlpListOffset;
		// Index to traverse the rlpPath
		short pathIndex = 0;

		// Traverse the RLP path
		while (pathIndex < rlpPathLength) {
			byte pathSegment = rlpPath[(short) (rlpPathOffset + pathIndex)];
			pathIndex++;
			// Decode current element in the list
			int prefix = rlpList[listIndex] & 0xFF;
			if ((prefix & 0xFF) <= 0x7F) {
				// Single byte value (0x00 - 0x7F)
				listIndex++;
			} else if ((prefix & 0xFF) >= 0x80 && (prefix & 0xFF) <= 0xB7) {
				// Short string (0x80 - 0xB7)
				int length = prefix - 0x80;
				listIndex += length + 1;
			} else if ((prefix & 0xFF) >= 0xB8 && (prefix & 0xFF) <= 0xBF) {
				// Long string (0xB8 - 0xBF)
				int lengthOfLength = (prefix & 0xFF) - 0xB7;
				listIndex++;
				int length = 0;
				for (int i = 0; i < lengthOfLength; i++) {
					length = (length << 8) | (rlpList[listIndex] & 0xFF);
					listIndex++;
				}
				listIndex += length;
			} else if ((prefix & 0xFF) >= 0xC0 && (prefix & 0xFF) <= 0xF7) {
				// Short list (0xC0 - 0xF7)
				listIndex++;
				// Navigate through list items
				for (byte i = 0; i < pathSegment; i++) {
					int childPrefix = rlpList[listIndex] & 0xFF;
					if ((childPrefix & 0xFF) <= 0x7F) {
						// Single byte value
						listIndex++;
					} else if ((childPrefix & 0xFF) >= 0x80 && (childPrefix & 0xFF) <= 0xB7) {
						// Short string
						int childLength = childPrefix - 0x80;
						listIndex += childLength + 1;
					} else if ((childPrefix & 0xFF) >= 0xB8 && (childPrefix & 0xFF) <= 0xBF) {
						// Long string
						int childLengthOfLength = (childPrefix & 0xFF) - 0xB7;
						listIndex++;
						int childLength = 0;
						for (int j = 0; j < childLengthOfLength; j++) {
							childLength = (childLength << 8) | (rlpList[listIndex] & 0xFF);
							listIndex++;
						}
						listIndex += childLength;
					} else if ((childPrefix & 0xFF) >= 0xC0 && (childPrefix & 0xFF) <= 0xF7) {
						// Short list
						int childLength = childPrefix - 0xC0;
						listIndex += childLength + 1;
					} else if ((childPrefix & 0xFF) >= 0xF8 && (childPrefix & 0xFF) <= 0xFF) {
						// Long list
						int childLengthOfLength = (childPrefix & 0xFF) - 0xF7;
						listIndex++;
						int childLength = 0;
						for (int j = 0; j < childLengthOfLength; j++) {
							childLength = (childLength << 8) | (rlpList[listIndex] & 0xFF);
							listIndex++;
						}
						listIndex += childLength;
					} else {
						ISOException.throwIt(ErrorMessage._6EB0);
					}
					if (listIndex >= rlpListOffset + rlpListLength) {
						ISOException.throwIt(ErrorMessage._6EB1);
					}
				}
			} else if ((prefix & 0xFF) >= 0xF8 && (prefix & 0xFF) <= 0xFF) {
				// Long list (0xF8 - 0xFF)
				int lengthOfLength = prefix - 0xF7;
				listIndex++;
				short length = 0;
				for (int i = 0; i < lengthOfLength; i++) {
					length = (short) ((length << 8) | (rlpList[listIndex] & 0xFF));
					listIndex++;
				}

				if (listIndex + length > rlpListOffset + rlpListLength) {
					ISOException.throwIt(ErrorMessage._6EB2);
				}
				// Navigate through list items
				for (byte i = 0; i < pathSegment; i++) {
					int childPrefix = rlpList[listIndex] & 0xFF;
					if ((childPrefix & 0xFF) <= 0x7F) {
						// Single byte value
						listIndex++;
					} else if ((childPrefix & 0xFF) >= 0x80 && (childPrefix & 0xFF) <= 0xB7) {
						// Short string
						short childLength = (short) (childPrefix - 0x80);
						listIndex += childLength + 1;
					} else if ((childPrefix & 0xFF) >= 0xB8 && (childPrefix & 0xFF) <= 0xBF) {
						// Long string
						int childLengthOfLength = (childPrefix & 0xFF) - 0xB7;
						listIndex++;
						short childLength = 0;
						for (int j = 0; j < childLengthOfLength; j++) {
							childLength =
									(short) ((childLength << 8) | (rlpList[listIndex] & 0xFF));
							listIndex++;
						}
						listIndex += childLength;
					} else if ((childPrefix & 0xFF) >= 0xC0 && (childPrefix & 0xFF) <= 0xF7) {
						// Short list
						int childLength = childPrefix - 0xC0;
						listIndex += childLength + 1;
					} else if ((childPrefix & 0xFF) >= 0xF8 && (childPrefix & 0xFF) <= 0xFF) {
						// Long list
						int childLengthOfLength = (childPrefix & 0xFF) - 0xF7;
						listIndex++;
						int childLength = 0;
						for (int j = 0; j < childLengthOfLength; j++) {
							childLength = (childLength << 8) | (rlpList[listIndex] & 0xFF);
							listIndex++;
						}
						listIndex += childLength;
					} else {

					}
					if (listIndex >= rlpListOffset + rlpListLength) {
						ISOException.throwIt(ErrorMessage._6EB4);
					}
				}
			} else {
				ISOException.throwIt(ErrorMessage._6EB5);
			}
		}
		// Decode the final element at the resolved path
		int finalPrefix = rlpList[listIndex] & 0xFF;
		if ((finalPrefix & 0xFF) <= 0x7F) {
			// Single byte value (0x00 - 0x7F)
			dataOffset = listIndex;
			dataLength = 1;
		} else if ((finalPrefix & 0xFF) >= 0x80 && (finalPrefix & 0xFF) <= 0xB7) {
			// Short string (0x80 - 0xB7)
			dataOffset = (short) (listIndex + 1);
			dataLength = (short) (finalPrefix - 0x80);
		} else if ((finalPrefix & 0xFF) >= 0xB8 && (finalPrefix & 0xFF) <= 0xBF) {
			// Long string (0xB8 - 0xBF)
			int lengthOfLength = (finalPrefix & 0xFF) - 0xB7;
			listIndex++;
			int length = 0;
			for (int i = 0; i < lengthOfLength; i++) {
				length = (length << 8) | (rlpList[listIndex] & 0xFF);
				listIndex++;
			}
			if (length > 32767) {
				ISOException.throwIt(ErrorMessage._6EB6);
			}
			dataOffset = listIndex;
			dataLength = (short) length;
		} else if ((finalPrefix & 0xFF) >= 0xC0 && (finalPrefix & 0xFF) <= 0xF7) {
			// Short list (0xC0 - 0xF7) — content only, header excluded
			listIndex++;
			dataOffset = listIndex;
			dataLength = (short) (finalPrefix - 0xC0);
		} else if ((finalPrefix & 0xFF) >= 0xF8 && (finalPrefix & 0xFF) <= 0xFF) {
			// Long list (0xF8 - 0xFF) — content only, header excluded
			int lengthOfLength = (finalPrefix & 0xFF) - 0xF7;
			listIndex++;
			int length = 0;
			for (int i = 0; i < lengthOfLength; i++) {
				length = (length << 8) | (rlpList[listIndex] & 0xFF);
				listIndex++;
			}
			if (length > 32767) {
				ISOException.throwIt(ErrorMessage._6EB6);
			}
			dataOffset = listIndex;
			dataLength = (short) length;
		} else {
			ISOException.throwIt(ErrorMessage._6EB7);
		}
	}

	// public static void decodeByIndex(byte[] rlpList, short rlpListOffset,
	// short rlpListLength, byte index) {
	// path[pathOffset] = index;
	// RlpDataParser.execute(rlpList, rlpListOffset, rlpListLength, path,
	// pathOffset, (short) 1);
	// }

	// Unlike execute()/decodeByIndex(), listContent/contentOffset/contentLength
	// here is NOT a value with its own RLP header — it's the already-resolved,
	// header-stripped CONTENT of a list (e.g. straight from getDataOffset()/
	// getDataLength() on a prior list result), i.e. its child elements
	// concatenated back-to-back. This walks past the first `index` siblings
	// and decodes the one at `index` (content only, same as execute()).
	public static void decodeChildByIndex(byte[] listContent, short contentOffset,
			short contentLength, byte index) {
		short contentEnd = (short) (contentOffset + contentLength);
		short elementOffset = contentOffset;
		for (byte i = 0; i < index; i++) {
			elementOffset = skipElement(listContent, elementOffset);
			if (elementOffset >= contentEnd) {
				ISOException.throwIt(ErrorMessage._6EB1);
			}
		}
		decodeElement(listContent, elementOffset);
	}

	// Returns the offset just past the whole RLP element (header + content)
	// starting at `offset`.
	private static short skipElement(byte[] data, short offset) {
		int prefix = data[offset] & 0xFF;
		if (prefix <= 0x7F) {
			return (short) (offset + 1);
		} else if (prefix <= 0xB7) {
			return (short) (offset + 1 + (prefix - 0x80));
		} else if (prefix <= 0xBF) {
			int lengthOfLength = prefix - 0xB7;
			int length = 0;
			for (int i = 0; i < lengthOfLength; i++) {
				length = (length << 8) | (data[(short) (offset + 1 + i)] & 0xFF);
			}
			return (short) (offset + 1 + lengthOfLength + length);
		} else if (prefix <= 0xF7) {
			return (short) (offset + 1 + (prefix - 0xC0));
		} else {
			int lengthOfLength = prefix - 0xF7;
			int length = 0;
			for (int i = 0; i < lengthOfLength; i++) {
				length = (length << 8) | (data[(short) (offset + 1 + i)] & 0xFF);
			}
			return (short) (offset + 1 + lengthOfLength + length);
		}
	}

	// Decodes the element at `offset` into dataOffset/dataLength, content only
	// (header excluded), same convention as execute().
	private static void decodeElement(byte[] data, short offset) {
		int prefix = data[offset] & 0xFF;
		if (prefix <= 0x7F) {
			dataOffset = offset;
			dataLength = 1;
		} else if (prefix <= 0xB7) {
			dataOffset = (short) (offset + 1);
			dataLength = (short) (prefix - 0x80);
		} else if (prefix <= 0xBF) {
			int lengthOfLength = prefix - 0xB7;
			int length = 0;
			for (int i = 0; i < lengthOfLength; i++) {
				length = (length << 8) | (data[(short) (offset + 1 + i)] & 0xFF);
			}
			if (length > 32767) {
				ISOException.throwIt(ErrorMessage._6EB6);
			}
			dataOffset = (short) (offset + 1 + lengthOfLength);
			dataLength = (short) length;
		} else if (prefix <= 0xF7) {
			dataOffset = (short) (offset + 1);
			dataLength = (short) (prefix - 0xC0);
		} else {
			int lengthOfLength = prefix - 0xF7;
			int length = 0;
			for (int i = 0; i < lengthOfLength; i++) {
				length = (length << 8) | (data[(short) (offset + 1 + i)] & 0xFF);
			}
			if (length > 32767) {
				ISOException.throwIt(ErrorMessage._6EB6);
			}
			dataOffset = (short) (offset + 1 + lengthOfLength);
			dataLength = (short) length;
		}
	}
}

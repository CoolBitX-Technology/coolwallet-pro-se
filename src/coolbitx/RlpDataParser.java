package coolbitx;

import javacard.framework.ISOException;

public class RlpDataParser {

	private static short dataOffset;
	private static short dataLength;

	public static short getDataOffset() {
		return dataOffset;
	}

	public static short getDataLength() {
		return dataLength;
	}

	public static void execute(byte[] rlpList, short rlpListOffset,
			short rlpListLength, byte[] rlpPath, short rlpPathOffset,
			short rlpPathLength) {

		short pathIndex = 0; // Index to traverse the rlpPath
		short listIndex = rlpListOffset; // Current index in the RLP
											// list
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
					} else if ((childPrefix & 0xFF) >= 0x80
							&& (childPrefix & 0xFF) <= 0xB7) {
						// Short string
						int childLength = childPrefix - 0x80;
						listIndex += childLength + 1;
					} else if ((childPrefix & 0xFF) >= 0xB8
							&& (childPrefix & 0xFF) <= 0xBF) {
						// Long string
						int childLengthOfLength = (childPrefix & 0xFF) - 0xB7;
						listIndex++;
						int childLength = 0;
						for (int j = 0; j < childLengthOfLength; j++) {
							childLength = (childLength << 8)
									| (rlpList[listIndex] & 0xFF);
							listIndex++;
						}
						listIndex += childLength;
					} else if ((childPrefix & 0xFF) >= 0xC0
							&& (childPrefix & 0xFF) <= 0xF7) {
						// Short list
						int childLength = childPrefix - 0xC0;
						listIndex += childLength + 1;
					} else if ((childPrefix & 0xFF) >= 0xF8
							&& (childPrefix & 0xFF) <= 0xFF) {
						// Long list
						int childLengthOfLength = (childPrefix & 0xFF) - 0xF7;
						listIndex++;
						int childLength = 0;
						for (int j = 0; j < childLengthOfLength; j++) {
							childLength = (childLength << 8)
									| (rlpList[listIndex] & 0xFF);
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
					} else if ((childPrefix & 0xFF) >= 0x80
							&& (childPrefix & 0xFF) <= 0xB7) {
						// Short string
						short childLength = (short) (childPrefix - 0x80);
						listIndex += childLength + 1;
					} else if ((childPrefix & 0xFF) >= 0xB8
							&& (childPrefix & 0xFF) <= 0xBF) {
						// Long string
						int childLengthOfLength = (childPrefix & 0xFF) - 0xB7;
						listIndex++;
						short childLength = 0;
						for (int j = 0; j < childLengthOfLength; j++) {
							childLength = (short) ((childLength << 8) | (rlpList[listIndex] & 0xFF));
							listIndex++;
						}
						listIndex += childLength;
					} else if ((childPrefix & 0xFF) >= 0xC0
							&& (childPrefix & 0xFF) <= 0xF7) {
						// Short list
						int childLength = childPrefix - 0xC0;
						listIndex += childLength + 1;
					} else if ((childPrefix & 0xFF) >= 0xF8
							&& (childPrefix & 0xFF) <= 0xFF) {
						// Long list
						int childLengthOfLength = (childPrefix & 0xFF) - 0xF7;
						listIndex++;
						int childLength = 0;
						for (int j = 0; j < childLengthOfLength; j++) {
							childLength = (childLength << 8)
									| (rlpList[listIndex] & 0xFF);
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
			dataOffset = listIndex;
			dataLength = (short) length;
		} else if ((finalPrefix & 0xFF) >= 0xC0 && (finalPrefix & 0xFF) <= 0xF7) {
			// Short list (0xC0 - 0xF7)
			dataOffset = listIndex;
			dataLength = (short) (finalPrefix - 0xC0 + 1);
		} else if ((finalPrefix & 0xFF) >= 0xF8 && (finalPrefix & 0xFF) <= 0xFF) {
			// Long list (0xF8 - 0xFF)
			int lengthOfLength = (finalPrefix & 0xFF) - 0xF7;
			listIndex++;
			int length = 0;
			for (int i = 0; i < lengthOfLength; i++) {
				length = (length << 8) | (rlpList[listIndex] & 0xFF);
				listIndex++;
			}
			dataOffset = listIndex;
			dataLength = (short) length;
		} else {
			ISOException.throwIt(ErrorMessage._6EB6);
		}
	}

}

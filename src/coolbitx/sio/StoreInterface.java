/**
 * 
 */
package coolbitx.sio;

import javacard.framework.Shareable;

/**
 * 
 * @author Hank Liu <hankliu@coolbitx.com>
 */
public interface StoreInterface extends Shareable {
	// determine if have backup data
	public boolean isDataBackup();

	// set data
	public void setData(byte[] buf, short offset, short length, byte seqNo,
			boolean isLastData);

	// get data length
	public short getDataLength();

	// get data
	public short getData(byte[] destBuf, short destOffset, byte seqNo);

	// reset seed
	public void reset();

	// get card id
	public short getCardId(byte[] destBuf, short destOffset);

	// get key
	public short getKey(byte[] destBuf, short destOffset);

}

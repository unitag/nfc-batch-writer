package com.unitag.ncfwriter;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.smartcardio.*;

import org.nfctools.NfcException;
import org.nfctools.mf.ul.CapabilityBlock;
import org.nfctools.mf.ul.MemoryLayout;
import org.nfctools.ndef.NdefContext;
import org.nfctools.ndef.Record;
import org.nfctools.ndef.ext.AndroidApplicationRecord;
import org.nfctools.ndef.wkt.records.Action;
import org.nfctools.ndef.wkt.records.ActionRecord;
import org.nfctools.ndef.wkt.records.SmartPosterRecord;
import org.nfctools.ndef.wkt.records.TextRecord;
import org.nfctools.ndef.wkt.records.UriRecord;
import org.nfctools.tags.TagOutputStream;

/**
 * Encodes and writes the records read in the csv file passed in parameter in Mifare Ultralight-derived tags using an ACR122U reader.
 * Informations about the format of the csv file and the type of records available can be found in the README included in this project.
 * For more informations on the syntax of the messages sent to the reader, please consult the ACR122U documentation here :
 * http://downloads.acs.com.hk/drivers/en/API-ACR122U-2.02.pdf
 * 
 */
public class NFCWriter {

	//Escape IOCTL(3500) character allowing us to control the reader without any tag detected
	//Note that the code is specific to Linux, Windows user will need to use the value 0x003136B0 instead
	final static int IOCTL_SMARTCARD_ACR122_ESCAPE_COMMAND = 0x42000DAC;

	public static void main(String[] args) {

		ArrayList<String[]> array = new ArrayList<String[]>();
		boolean setReadOnly;

		try {

			// Open the csv file and read its content (one line per tag)
			BufferedReader buffer = new BufferedReader(new FileReader(args[0]));
			String line = "";
			while ((line = buffer.readLine()) != null) array.add(line.split(";"));
			buffer.close();

			//Initialize the reader
			CardTerminal terminal = init_reader();
			Card card = null;

			String readOnly = array.get(0)[0];
			if (readOnly.equals("false")) {
				setReadOnly = false;
				System.out.println("Tags will not be set to ReadOnly");
			} else if (readOnly.equals("true")) {
				setReadOnly = true;
				System.out.println("Tags will be set to ReadOnly");
			} else {
				throw new NfcException("Couldn't determine if the tags have to be set read-only");
			}

			for (int tags=1; tags<array.size(); tags++) {
				try {

					//Encode the records into a binary array
					byte[] msg = encode_record(array.get(tags));

					//Write the output stream
					MemoryLayout memorylayout = MemoryLayout.ULTRALIGHT_C;
					TagOutputStream output = new TagOutputStream(memorylayout.getMaxSize());
					//TLV Lock
					output.write(0x01);												//Identifier (0x01 = Lock)
					output.write(0x03);												//Lock length, so 3
					output.write(memorylayout.createLockControlTlv().toBytes());	//Value
					//TLV NDEF message
					output.write(0x03);					//Identifier (0x03 = NDEF message)
					output.write(msg.length);			//Message length
					output.write(msg, 0, msg.length);	//Value
					//TLV Terminator
					output.write(0xFE);
					//Pad with zeroes in order to get full pages - we shouldn't get maximum size problems as a full
					//memory contains full pages
					int bpp = memorylayout.getBytesPerPage();
					for (int i=0; i<(bpp-(output.getRemainingSize()%bpp)); i++) output.write(0);
					//Get the binary array
					byte[] data = output.getBuffer();
					output.close();

					// Wait for a tag do be discovered
					boolean tag_discovered = false;
					while (!tag_discovered) {
						try {
							card = terminal.connect("*");
							tag_discovered = true;
						} catch (CardException e) {
							// No tag detected yet, so ignore and sleep a bit
							try {
								Thread.sleep(500);
							} catch (InterruptedException e1) {
								Thread.currentThread().interrupt();
							}
						}
					}
					CardChannel channel = card.getBasicChannel();

					//Write the data in the tag
					for (int i=0; i<(data.length/bpp); i++) {
						byte[] cmd = {(byte) 0xFF, (byte) 0xD6, 0x00, (byte) (i+memorylayout.getFirstDataPage()), 0x04,
								data[bpp*i], data[bpp*i+1], data[bpp*i+2], data[bpp*i+3]};
						channel.transmit(new CommandAPDU(cmd));
					}

					//Mark tag as read-only when applicable
					//WARNING : Cannot be reverted
					if (setReadOnly) {
						CapabilityBlock capa = memorylayout.createCapabilityBlock();
						capa.setReadOnly();
						byte[] capability = capa.getData();
						byte[] cmd = {(byte) 0xFF, (byte) 0xD6, 0x00, (byte) memorylayout.getCapabilityPage(), 0x04,
								capability[0], capability[1], capability[2], capability[3]};
						channel.transmit(new CommandAPDU(cmd));
					}
					System.out.print("done");
					System.out.println();

					// Blink the LED
					// Note on the fields :	Byte 4 -> LED status control, Byte 6-7 -> T1-T2 duration (initial and toggle blinking),
					//						Byte 8 -> Number of repetitions, Byte 9 -> Link to buzzer
					byte[] cmd_led = {(byte) 0xFF, 0x00, 0x40, (byte) 0b11110000, 0x04, 0x02, 0x02, 0x0A, 0x00};
					channel.transmit(new CommandAPDU(cmd_led));

					//Disconnect the tag
					card.disconnect(false);

				} catch (NfcException e) {
					//The current line had no valid record
					System.out.println("Line could not be parsed correctly, the program will continue to the next line");
				}
			}
			System.out.println("End of file reached");

		} catch (CardException e) {
			//Card could not be connected correctly
			e.printStackTrace();
		} catch (IOException e) {
			//Error reading the csv file
			e.printStackTrace();
		} catch (NfcException e) {
			//Error parsing the file
			e.printStackTrace();
		}
	}

	/**
	 * Initializes the card reader, turns off the buzzer sound and returns the card terminal
	 * 
	 * @return CardTerminal
	 * @throws CardException
	 */
	public static CardTerminal init_reader() throws CardException {

		// Display the list of terminals
		TerminalFactory factory = TerminalFactory.getDefault();
		List<CardTerminal> terminals = factory.terminals().list();
		System.out.println("Terminals : " + terminals);

		// Use the first terminal
		CardTerminal terminal = terminals.get(0);

		// Connect with the card using direct mode (allows connecting when there is no tag detected)
		Card card = terminal.connect("direct");
		System.out.println("Card connected : " + card);

		// Silence the buzzer
		// Byte 4 -> Buzzer State (0x00->OFF, 0xFF->ON)
		byte[] cmd_buz = {(byte) 0xFF, 0x00, 0x52, 0x00, 0x00};
		byte[] ans_buz = card.transmitControlCommand(IOCTL_SMARTCARD_ACR122_ESCAPE_COMMAND, cmd_buz);
		int ans_value = (ans_buz[0]<<8 | ans_buz[1]) & 0x0000FFFF;
		System.out.println("Buzzer silenced : SW=" + String.format("0x%4s", Integer.toHexString(ans_value)));

		// Disconnect the direct connection
		card.disconnect(false);
		System.out.println("Ready to write on tags");
		System.out.println();
		return terminal;
	}

	/**
	 * Puts the current line in a record based on its content and encodes the record.
	 * Supports multiple record per line, resulting to multiple record per tag
	 * 
	 * @param param	The parsed line
	 * @return Records encoded in a byte array
	 * @throws IOException
	 */
	public static byte[] encode_record(String[] param) {

		ArrayList<Record> records = new ArrayList<Record>();
		int index = 0;
		boolean endofline = false;

		System.out.println("Writing :");
		while (!endofline) {
			try {
				switch (param[index]) {
				case "text" :
					records.add(new TextRecord(param[index+1]));
					System.out.println("\t" + param[index] + " " + param[index+1]);
					index+=2;
					break;
				case "uri" :
					records.add(new UriRecord(param[index+1]));
					System.out.println("\t" + param[index] + " " + param[index+1]);
					index+=2;
					break;
				case "aar" :
					records.add(new AndroidApplicationRecord(param[index+1]));
					System.out.println("\t" + param[index] + " " + param[index+1]);
					index+=2;
					break;
				case "bookmark" :
					records.add(new SmartPosterRecord(new TextRecord(param[index+1]), new UriRecord(param[index+2]), new ActionRecord(Action.getActionByValue((byte) 0))));
					System.out.println("\t" + param[index] + " " + param[index+1]);
					index+=3;
					break;
				case "sms" :
					records.add(new SmartPosterRecord(new TextRecord(param[index+1]), new UriRecord("sms:" + param[index+2] + "?body=" + param[index+3]), new ActionRecord(Action.getActionByValue((byte) 0))));
					System.out.println("\t" + param[index] + " " + param[index+1]);
					index+=4;
					break;
				case "mail" :
					records.add(new SmartPosterRecord(new TextRecord(param[index+1]), new UriRecord("mailto:" + param[index+2] + "?subject=" + param[index+3] + "&body=" + param[index+4]), new ActionRecord(Action.getActionByValue((byte) 0))));
					System.out.println("\t" + param[index] + " " + param[index+1]);
					index+=5;
					break;
				case "tel" :
					records.add(new SmartPosterRecord(new TextRecord(param[index+1]), new UriRecord("tel:" + param[index+2]), new ActionRecord(Action.getActionByValue((byte) 0))));
					System.out.println("\t" + param[index] + " " + param[index+1]);
					index+=3;
					break;
				case "geo" :
					records.add(new SmartPosterRecord(new TextRecord(param[index+1]), new UriRecord("geo:" + param[index+2] + "," + param[index+3]), new ActionRecord(Action.getActionByValue((byte) 0))));
					System.out.println("\t" + param[index] + " " + param[index+1]);
					index+=4;
					break;
				default :
					throw new NfcException("Unknown record type " + param[index]);
				}
				endofline = index<param.length ? false : true;
			} catch (NfcException e) {
				//Type of record unknown
				System.out.println("\tERROR : Unknown record type " + param[index] + ", ignoring the rest of the line");
				endofline = true;
			} catch (ArrayIndexOutOfBoundsException e) {
				//Not enough fields for the declared type
				System.out.println("\tERROR : Not enough fields for the type " + param[index] + ", ignoring the rest of the line");
				endofline = true;
			}
		}
		System.out.print("... ");
		if (records.size()==0) {
			System.out.println("error");
			throw new NfcException("Line could not the parsed correctly");
		}

		return NdefContext.getNdefMessageEncoder().encode(records);

	}

}

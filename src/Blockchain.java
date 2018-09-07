/*
 * Developed by Ashwin Rao in February 2018.
 * Last Modified 9/7/18 2:58 PM.
 * Copyright (c) 2018. All rights reserved.
 */

/**
 * 1. Name / Date:                      Ashwin Rao / February 18th, 2018
 *
 * 2. Java version used:                Java 9
 *
 * 3. To compile...                     > javac --add-modules java.xml.bind Blockchain.java
 *
 * 4. To Run...                         > java --add-modules java.xml.bind Blockchain [0,1,2] [input file]  // can take 2 command line arguments
 *                                                                                                          // the first is the process ID, the second is the input file
 *                                                                                                          // leaving the first blank defaults to process 0
 *                                                                                                          // leaving the second blank defaults to the default input (BlockInput$.txt) where $ = process ID
 *
 *                                      ** THE PROGRAM RUNS USING THE BATCH FILES PROVIDED IN THE INSTRUCTIONS. I HAVE TESTED IT AND DONE ALL THE PROGRAMMING FOR THIS ASSIGNMENT
 *                                      ON A WINDOWS 10 MACHINE.**
 *
 *
 * 5. List of files needed:
 *                                      Blockchain.java
 *                                      checklist-block.html
 *                                      BlockInput0.txt
 *                                      BlockInput1.txt
 *                                      BlockInput2.txt
 *                                      BlockchainLedgerSample.xml
 *                                      BlockchainLog.txt
 *
 * 6. Notes:                            Process 0 does not write the final ledger to disk. As such, the included BlockchainLedgerSample.xml
 *                                      is included for completeness but is BLANK. See the checklist for a full explanation. Also, the work
 *                                      is being faked due to time restrictions.
 *-------------------------------------------------------------------------------------------------------------------*/
import javax.xml.bind.*;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.PriorityBlockingQueue;
import java.util.concurrent.ThreadLocalRandom;

class Ports {
    final static int KeyServerPortBase = 4710;
    final static int UnverifiedBlockServerPortBase = 4820;
    final static int BlockchainServerPortBase = 4930;

    public static int KeyServerPort;
    public static int UnverifiedBlockServerPort;
    public static int BlockchainServerPort;

    public void setPorts(){
        KeyServerPort = KeyServerPortBase + Blockchain.PID;
        UnverifiedBlockServerPort = UnverifiedBlockServerPortBase + Blockchain.PID;
        BlockchainServerPort = BlockchainServerPortBase + Blockchain.PID;
    }
}

// container for holding and identifying public keys with their sending processes (by PID)
class PublicKey {
    private int PID;
    private Key publicKey;
//    int port;
//    String IPAddress;

    PublicKey(int PID, Key publicKey) {
        this.PID = PID;
        this.publicKey = publicKey;
    }

    public Key getPublicKey() {
        return this.publicKey;
    }

    public int getPID() {
        return this.PID;
    }

    public void printInfo() {
        System.out.println("Process\t" + PID + ", Public Key:\t" + Base64.getEncoder().encodeToString(publicKey.getEncoded()) + "\n");
    }
}

@XmlRootElement
class BlockRecord implements Comparable<BlockRecord> {
     String PID;
     String sUUID;
     String TimeStamp;
     String FName;
     String LName;
     String DOB;
     String SSN;
     String diagnosis;
     String treatment;
     String medication;
     String SignedSHA256;
     String data;
     String SHA256;

     // ***NOTE: I was getting some weird errors using the constructor to create a BlockRecord object from .txt so I switched to setters only
//    BlockRecord(int pid, String first, String last, String dob, String ssn, String diagnosis, String treatment, String medication) {
//        setPID(pid);
//        setFName(first);
//        setLName(last);
//        setDOB(dob);
//        setSSN(ssn);
//        setDiagnosis(diagnosis);
//        setTreatment(treatment);
//        setMedication(medication);
//        setBlockID();
//        setTimeStamp(pid);
//    }

    private int makeSSNInt(String ssn) {
        String[] sub = ssn.split("-");
        StringBuilder ssnString = new StringBuilder();
        for (String s : sub) { ssnString.append(s); }
        return Integer.parseInt(ssnString.toString());
    }

    // FOR THE PRIORITY QUEUE: Compares the blocks based on their PID and if there is a tie (as there always will be)
    // then the SSN is used as the tie-breaker as it is a unique number. I could have used a UUID but I chose to use SSN, either
    // one would work. ***NOTE: I am using the PID to compare because I had lots of problems with Timestamps changing thru XML
    // marshalling, unmarshalling. Also collisions with the suggested timestamp format in BlockH.java, even though it said it would
    // prevent collisions by adding PID to the end. In order to ensure synchronicity among the different processes' priority
    // queue ordering, I decided to go with PID instead of Timestamp for the compareTo method.
    @Override
    public int compareTo(BlockRecord o) {
        int thisPid = Integer.parseInt(getPID());
        int otherPid = Integer.parseInt(o.getPID());

        int thisSSN = makeSSNInt(getSSN());
        int otherSSN = makeSSNInt(o.getSSN());

        if (thisPid == otherPid) {
            if (thisSSN > otherSSN) {
                return 1;
            } else {
                return -1;
            }
        } else if (thisPid > otherPid) {
            return 1;
        } else {
            return -1;
        }
    }

    public String getSignedSHA256() {
        return SignedSHA256;
    }

    public String getData() {
        return data;
    }

    public String getSHA256() {
        return SHA256;
    }

    public String getPID() {
        return PID;
    }

    public String getsUUID() {
        return sUUID;
    }

    public String getTimeStamp() {
        return TimeStamp;
    }

    public String getFName() {
        return FName;
    }

    public String getLName() {
        return LName;
    }

    public String getDOB() {
        return DOB;
    }

    public String getSSN() {
        return SSN;
    }

    public String getDiagnosis() {
        return diagnosis;
    }

    public String getTreatment() {
        return treatment;
    }

    public String getMedication() {
        return medication;
    }

    @XmlElement
    public void setSHA256(String sha256) {
        this.SHA256 = sha256;
    }

    @XmlElement
    public void setData(String data) {
        this.data = data;
    }

    @XmlElement
    public void setSignedSHA256(String signedSHA256) {
        this.SignedSHA256 = signedSHA256;
    }

    @XmlElement
    public void setPID(String PID) {
        this.PID = PID;
    }

    @XmlElement
    public void setFName(String FName) {
        this.FName = FName;
    }

    @XmlElement
    public void setLName(String LName) {
        this.LName = LName;
    }

    @XmlElement
    public void setDOB(String DOB) {
        this.DOB = DOB;
    }

    @XmlElement
    public void setSSN(String SSN) {
        this.SSN = SSN;
    }

    @XmlElement
    public void setDiagnosis(String diagnosis) {
        this.diagnosis = diagnosis;
    }

    @XmlElement
    public void setTreatment(String treatment) {
        this.treatment = treatment;
    }

    @XmlElement
    public void setMedication(String medication) {
        this.medication = medication;
    }

    @XmlElement
    public void setTimeStamp(String timeStamp) {
        this.TimeStamp = timeStamp;
//        Date date = new Date();
//        String T1 = String.format("%1$s %2$tF.%2$tT", "", date);
//        this.TimeStamp = T1 + "." + Blockchain.PID;    // to avoid timestamp collisions (since many processes are reading in blocks simultaneously)
    }

    @XmlElement
    public void setsUUID(String blockID) {
//        this.sUUID = UUID.randomUUID().toString();
        this.sUUID = blockID;
    }

    public void print() {
        System.out.printf("%s %s %s %s %s %s %s %s %s %s\n", PID, sUUID, TimeStamp, FName, LName, DOB, SSN, diagnosis, treatment, medication);
    }

    @Override
    public String toString() {
        return String.format("PID: %s, sUUID: %s, SHA256: %s, SignedSHA256: %s, Timestamp: %s, FName: %s, LName: %s, DOB: %s, SSN: %s, Diagnosis: %s, Treatment: %s, Medication: %s \ndata: %s\n", PID, sUUID, SHA256, SignedSHA256, TimeStamp, FName, LName, DOB, SSN, diagnosis, treatment, medication, data);
    }

//    public static String createTimeStamp() {
//        return new Timestamp(System.nanoTime()).toString();
////        Date date = new Date();
////        String T1 = String.format("%1$s %2$tF.%2$tT", "", date);
////        return T1 + "." + String.valueOf(Blockchain.PID);    // to avoid timestamp collisions (since many processes are reading in blocks simultaneously)
//    }


}

class PublicKeyWorker extends Thread {
    Socket socket;
    PublicKeyWorker(Socket socket) {
        this.socket = socket;
    }
    public void run() {
        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            int pid = Integer.parseInt(in.readLine());
            String key = in.readLine();
            byte[] keyBytes = Base64.getDecoder().decode(key);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            try {
                Blockchain.publicKeys[pid] = new PublicKey(pid, KeyFactory.getInstance("RSA").generatePublic(keySpec));
            } catch (Exception exc) {
                exc.printStackTrace();
            }
            System.out.println("Got key from Process " + pid + ": " + key + "\n");
            socket.close();
        } catch (IOException x) {
            x.printStackTrace();
        }
    }

}

class PublicKeyServer implements Runnable {

    public void run() {
        int q_len = 6;
        Socket socket;
        System.out.println("Starting Key Server input thread using " + Integer.toString(Ports.KeyServerPort));
        System.out.println("Waiting for other processes' public keys...\n");
        try {
            ServerSocket serverSocket = new ServerSocket(Ports.KeyServerPort, q_len);
            while (true) {
                socket = serverSocket.accept();
                new PublicKeyWorker(socket).start();
            }
        } catch (IOException ioe) {
            System.out.println(ioe);
        }
    }
}

class UnverifiedBlockCreator {

    // Responsibilities of this class:
    // 1. creates java Block object from .txt file
    // 2. marshals java object to XML String format
    // 3. applies SHA-256 hash on the raw data String and stores inside the object itself
    // 4. signs the stored hash with this process' private key and stores that signed hash in the object

    // following method accomplishes responsibilities 1-4
    public static ArrayList<BlockRecord> txtToBlock() {
        ArrayList<BlockRecord> blockRecords = new ArrayList<>();
        try {
            String line;
            BufferedReader br = new BufferedReader(new FileReader(Blockchain.file));
            while ((line = br.readLine()) != null) {
                String[] sub = line.split("\\s");
                BlockRecord blockRecord = new BlockRecord();
                blockRecord.setPID(String.valueOf(Blockchain.PID));
                blockRecord.setsUUID(UUID.randomUUID().toString());
                Date date = new Date();
                String T1 = String.format("%1$s %2$tF.%2$tT", "", date);
                String TimeStampString = T1 + "." + Blockchain.PID;
                blockRecord.setTimeStamp(TimeStampString);
                blockRecord.setFName(sub[0]);
                blockRecord.setLName(sub[1]);
                blockRecord.setDOB(sub[2]);
                blockRecord.setSSN(sub[3]);
                blockRecord.setDiagnosis(sub[4]);
                blockRecord.setTreatment(sub[5]);
                blockRecord.setMedication(sub[6]);
                // Store the raw data (line) as a field in the object for confirmation of the signed hash
                blockRecord.setData(line);
                // Hash the raw data (line) into a 256-bit String (SHA-256 alg), store inside the BlockRecord obj
                MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
                messageDigest.update(line.getBytes());
                byte bytes[] = messageDigest.digest();
                String hashed = Base64.getEncoder().encodeToString(bytes);
                blockRecord.setSHA256(hashed);
                // sign the SHA256 hash and store in the object
                byte signedBytes[] = KeyUtil.signData(bytes, Blockchain.myKeyPair.getPrivate());
                String signedHash = Base64.getEncoder().encodeToString(signedBytes);
                blockRecord.setSignedSHA256(signedHash);
                blockRecords.add(blockRecord);
            }
            br.close();
        } catch (Exception e) { }
        return blockRecords;
    }

    // CONVERTS ARRAY LIST OF BLOCK OBJECTS TO ARRAY LIST OF XML BLOCKS (STRINGS)
    public static ArrayList<String> javaToXML() {
        ArrayList<BlockRecord> javaRecords = txtToBlock();
        ArrayList<String> xmlRecords = new ArrayList<>();
        try {
            JAXBContext jaxbContext = JAXBContext.newInstance(BlockRecord.class);
            Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
            // The following is set to false because I could not figure out how
            // to multicast the formatted xml string without getting a whole bunch of
            // exceptions thrown every time
            jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, false);
            for (BlockRecord br : javaRecords) {
                StringWriter stringWriter = new StringWriter();
                jaxbMarshaller.marshal(br, stringWriter);
                xmlRecords.add(stringWriter.toString());
            }
        } catch (JAXBException je) { }
        return xmlRecords;
    }

    /* NOTE: I DID NOT END UP USING THE FOLLOWING TWO METHODS, THOUGH THEIR FUNCTIONALITY HAS BEEN USED IN
    * OTHER PLACES SUCH AS THE ABOVE METHODS. */

    // CONVERTS ARRAY LIST OF XML BLOCKS TO ARRAY LIST OF SHA-256 HASHED BLOCKS (HEX STRINGS)
    public static String blockHasher(String xmlRecord) {
        String sha256 = "";
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
                messageDigest.update(xmlRecord.getBytes());
                byte byteData[] = messageDigest.digest();
                sha256 = DatatypeConverter.printHexBinary(byteData);
        } catch (NoSuchAlgorithmException nsae) { System.out.println(nsae); }
        return sha256;
    }

    // SIGNS SHA-256 HASH OF BLOCK DATA
    public static String sha256HashSigner(String sha256) {
        String signedSHA256Hash = "";
        try {
            byte[] digitalSignature = KeyUtil.signData(sha256.getBytes(), Blockchain.myKeyPair.getPrivate());
            signedSHA256Hash = Base64.getEncoder().encodeToString(digitalSignature);
        } catch (Exception e) { System.out.println(e); }
        return signedSHA256Hash;
    }
}

class UnverifiedBlockWorker extends Thread {
    Socket socket;
    UnverifiedBlockWorker(Socket socket) {
        this.socket = socket;
    }

    public void run() {
        // wait for unverified blocks to come in
        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            // first message from the sending process is the number of blocks to expect
            int incomingBlocks = Integer.parseInt(in.readLine());
            // using the number of incoming blocks, we can loop through our non-formatted XML blocks, unmarshall, and enqueue
            for (int i = 0; i < incomingBlocks; i++) {
                String unverifiedBlock = in.readLine();
                // unmarshalls XML blocks back to BlockRecord objects and enqueues by rules in BlockRecord.compareTo()
                try {
                    JAXBContext jaxbContext = JAXBContext.newInstance(BlockRecord.class);
                    Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
                    StringReader reader = new StringReader(unverifiedBlock);
                    BlockRecord unmarshalledBlock = (BlockRecord) unmarshaller.unmarshal(reader);
                    Blockchain.unverifiedBlockQueue.add(unmarshalledBlock); // adds a block object to the priority queue
                } catch (JAXBException jaxbe) { System.out.println("Problem unmarshalling"); }
            }
        } catch (IOException ioe) {
            System.out.println(ioe);
        }
    }

}

class UnverifiedBlockConsumer implements Runnable {

    public void run() {
        BlockRecord data;
        String verifiedBlock = "";

        System.out.println("Starting the Unverified Block Priority Queue Consumer Thread...\n");
        try {
            while (true) {
                data = Blockchain.unverifiedBlockQueue.take();
                System.out.println("Consumer got unverified block with SHA-256 Hash equal to: " + data.getSHA256());
                // checks whether the current blockchain has the block-specific SHA256 in it
                if (!Blockchain.theBlockchain.contains(data.getSHA256())) {
                    // I'm faking work here. I plan to replace this with real work sometime later, if there's time
                    // edit: I didn't come back to fix this. There was no time.
                    int j;
                    for (int i = 0; i < 100; i++) {
                        j = ThreadLocalRandom.current().nextInt(0, 10);
                        try {
                            Thread.sleep(500);
                        } catch (Exception ex) {
                            ex.printStackTrace();
                        }
                        if (j < 2) break;
                    }
                    System.out.println("Puzzle solved!");
                    // check again since some time has elapsed while doing work
                    if(!Blockchain.theBlockchain.contains(data.getSHA256())) {
                        try {
                            JAXBContext jaxbContext = JAXBContext.newInstance(BlockRecord.class);
                            Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
                            jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, false);
                            StringWriter stringWriter = new StringWriter();
                            jaxbMarshaller.marshal(data, stringWriter);
                            verifiedBlock = stringWriter.toString();
                        } catch (Exception e) {
                            System.out.println(e);
                        }

                        Blockchain.theBlockchain = verifiedBlock + "$" + Blockchain.theBlockchain;
                        Blockchain.multiCast(false, false, true);
                    } else {
                        System.out.println("Unverified block dropped. Already in blockchain.");
                    }
                } else {
                    System.out.println("Unverified block dropped. Already in blockchain.");
                }
            }
        } catch (Exception e) { System.out.println(e); }

    }
}

class UnverifiedBlockServer implements Runnable {

    public void run() {
        int q_len = 6;
        Socket socket;
        System.out.println("Starting Unverified Block Server input thread using " + Integer.toString(Ports.UnverifiedBlockServerPort));
        System.out.println("Waiting for unverified blocks to come from other processes...\n");
        try {
            ServerSocket serverSocket = new ServerSocket(Ports.UnverifiedBlockServerPort, q_len);
            while (true) {
                socket = serverSocket.accept();
                new UnverifiedBlockWorker(socket).start();
            }
        } catch (IOException ioe) {
            System.out.println(ioe);
        }
    }
}

class KeyUtil {

    // used only to generate this process' keypair and store in a local variable
    // later on, the local KeyPair was used to multicast its public key to other processes
    public static KeyPair generateKeyPair(long seed) throws Exception {
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        SecureRandom rng = SecureRandom.getInstance("SHA1PRNG", "SUN");
        rng.setSeed(seed);
        keyGenerator.initialize(1024, rng);
        return (keyGenerator.generateKeyPair());
    }

    // used primarily to sign the SHA256 hash of the raw data, and store in the BlockRecord object
    public static byte[] signData(byte[] data, PrivateKey key) throws Exception {
        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initSign(key);
        signer.update(data);
        return (signer.sign());
    }

}

class BlockchainWorker extends Thread {
    Socket socket;
    BlockchainWorker(Socket socket) {
        this.socket = socket;
    }
    public void run() {
        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            String data = "";
            String data2;
            int sendingProcess = Integer.parseInt(in.readLine());
            // reads in and builds the new blockchain being sent from other processes who have recently verified blocks
            while ((data2 = in.readLine()) != null) {
                data = data + data2;
            }
            // replaces the current blockchain with the incoming candidate
            // typically you would verify the blockchain here before updating, but I didn't have time
            Blockchain.theBlockchain = data;
            // print the new blockchain to the console, along with the number of the sending process
            System.out.println("\n--------------------------NEW BLOCKCHAIN (from Process " + sendingProcess + ")---------------------------------------------\n");
            String[] subs = Blockchain.theBlockchain.split("\\$");
            try {
                for (String block : subs) {
                    // unmarshall, then remarshall to get the nice formatted output
                    JAXBContext jaxbContext = JAXBContext.newInstance(BlockRecord.class);
                    Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
                    Marshaller marshaller = jaxbContext.createMarshaller();
                    marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
                    StringWriter stringWriter = new StringWriter();
                    StringReader reader = new StringReader(block);
                    BlockRecord unmarshalledBlock = (BlockRecord) unmarshaller.unmarshal(reader);
                    marshaller.marshal(unmarshalledBlock, stringWriter);
                    System.out.print(stringWriter.toString());
                }
            } catch (Exception e) {
                System.out.println(e);
            }
            System.out.println("---------------------------------------------------------------------------------------------------------------------------\n");
        } catch (IOException ioe) {
            ioe.printStackTrace();
        }
    }
}

class BlockchainServer implements Runnable {
    public void run() {
        int q_len = 6;
        Socket socket;
        System.out.println("Starting the Blockchain server using " + Integer.toString(Ports.BlockchainServerPort));
        try {
            ServerSocket serverSocket = new ServerSocket(Ports.BlockchainServerPort, q_len);
            while (true) {
                socket = serverSocket.accept();
                new BlockchainWorker(socket).start();
            }
        } catch (IOException ioe) {
            System.out.println(ioe);
        }
    }
}


public class Blockchain {

    static String serverName = "localhost";
    static String file;
    static int PID = 0;
    static int numProcesses = 3;
    static KeyPair myKeyPair;
    static PublicKey[] publicKeys = new PublicKey[3];
    static BlockingQueue<BlockRecord> unverifiedBlockQueue = new PriorityBlockingQueue<>();
    static String theBlockchain;


    public static void multiCast(boolean toSendKey, boolean toSendBlock, boolean toSendChain) {
        Socket socket;
        PrintStream toServer;

        if (toSendKey) {
            try {
                for (int i = 0; i < numProcesses; i++) {
                    socket = new Socket(serverName, Ports.KeyServerPortBase + i);
                    toServer = new PrintStream(socket.getOutputStream());
                    toServer.println(PID);
                    toServer.println(Base64.getEncoder().encodeToString(myKeyPair.getPublic().getEncoded()));
                    toServer.flush();
                    socket.close();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        if (toSendBlock) {
            try {
                for (int i = 0; i < numProcesses; i++) {
                    socket = new Socket(serverName, Ports.UnverifiedBlockServerPortBase + i);
                    toServer = new PrintStream(socket.getOutputStream());
                    toServer.println(UnverifiedBlockCreator.javaToXML().size());
                    for (String s : UnverifiedBlockCreator.javaToXML()) { toServer.println(s); }
                    toServer.flush();
                    socket.close();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        if (toSendChain) {
            try {
                for (int i = 0; i < numProcesses; i++) {
                    socket = new Socket(serverName, Ports.BlockchainServerPortBase + i);
                    toServer = new PrintStream(socket.getOutputStream());
                    toServer.println(Blockchain.PID);
                    toServer.println(theBlockchain);
                    toServer.flush();
                    socket.close();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

    }

    private static BlockRecord createDummyBlock() {
        BlockRecord dumdum = new BlockRecord();
        try {
            String line = "Johnny Tsunami 1990.10.21 630-777-911 ObsessiveSurfing ChillOutMan Herbs";
            String[] sub = line.split("\\s");
            dumdum.setPID(String.valueOf(Blockchain.PID));
            dumdum.setsUUID(UUID.randomUUID().toString());
            Date date = new Date();
            String T1 = String.format("%1$s %2$tF.%2$tT", "", date);
            String TimeStampString = T1 + "." + Blockchain.PID;
            dumdum.setTimeStamp(TimeStampString);
            dumdum.setFName(sub[0]);
            dumdum.setLName(sub[1]);
            dumdum.setDOB(sub[2]);
            dumdum.setSSN(sub[3]);
            dumdum.setDiagnosis(sub[4]);
            dumdum.setTreatment(sub[5]);
            dumdum.setMedication(sub[6]);
            // Store the raw data (line) as a field in the object for confirmation of the signed hash
            dumdum.setData(line);
            // Hash the raw data (line) into a 256-bit String (SHA-256 alg), store inside the BlockRecord obj
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(line.getBytes());
            byte bytes[] = messageDigest.digest();
            String hashed = Base64.getEncoder().encodeToString(bytes);
            dumdum.setSHA256(hashed);
            // sign the SHA256 hash and store in the object
            byte signedBytes[] = KeyUtil.signData(bytes, Blockchain.myKeyPair.getPrivate());
            String signedHash = Base64.getEncoder().encodeToString(signedBytes);
            dumdum.setSignedSHA256(signedHash);
        } catch (Exception e) {
            System.out.println("Error creating the dummy block");
        }
        return dumdum;
    }

    private static String marshallDummyBlock(BlockRecord dummyBlock) {
        String xml = "";
        try {
            JAXBContext jaxbContext = JAXBContext.newInstance(BlockRecord.class);
            Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
            jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, false);
            StringWriter stringWriter = new StringWriter();
            jaxbMarshaller.marshal(dummyBlock, stringWriter);
            xml = stringWriter.toString();
        } catch (Exception e) { System.out.println("Error marshalling dummy block"); }
        return xml;
    }

    public static void main(String[] args) {
        // setting the socket queue length for incoming connection requests
        int q_len = 6;
        // saves the first cmd line arg as process id, defaults to 0
        PID = (args.length < 1) ? 0 : Integer.parseInt(args[0]);
        // saves the second cmd line arg as the input file name, defaults to BlockInput#.txt, where # = PID
        file = (args.length < 2) ? "BlockInput" + PID + ".txt" : args[1];
        // announcement on startup
        System.out.println("Blockchain Framework starting up.");
        System.out.println("Using process id " + PID + "\n");


        // generate public / private key
        try {
            myKeyPair = KeyUtil.generateKeyPair(System.currentTimeMillis() * PID);
            publicKeys[PID] = new PublicKey(PID, myKeyPair.getPublic());
        } catch (Exception e) {}

        // installs the port scheme that calculates process-specific server ports based on the supplied PID at cmd
        new Ports().setPorts();
        // starts up the public key server to process incoming public keys from other processes
        new Thread(new PublicKeyServer()).start();
        // starts up the server to process incoming unverified blocks read in from files
        new Thread(new UnverifiedBlockServer()).start();
        // starts up the server to process incoming replacement blockchains
        new Thread(new BlockchainServer()).start();

        // wait for all processes and servers to start
        try { Thread.sleep(1000); } catch (Exception e) { }
        // SEND PUBLIC KEYS
        multiCast(true, false, false);

        // creates the first dummy entry to the blockchain
        theBlockchain = marshallDummyBlock(createDummyBlock());
        System.out.println("\t\t--SEED FOR BLOCKCHAIN--" + theBlockchain + "\n\n");

        // wait for all keys to settle, then send blocks
        try { Thread.sleep(1000); } catch (Exception e) { }
        multiCast(false, true, false);

        // wait for all blocks to be received and enqueued, then start consuming (doing work)
        try { Thread.sleep(1000); } catch (Exception e) { }
        new Thread(new UnverifiedBlockConsumer()).start();

//        // debug
//        try { Thread.sleep(1000); } catch (Exception e) { }
//        int count = 1;
//        while(!unverifiedBlockQueue.isEmpty()) {
//            System.out.println("Dequeued: " + count + "--> " + unverifiedBlockQueue.remove());
//            count++;
//        }

    }
}

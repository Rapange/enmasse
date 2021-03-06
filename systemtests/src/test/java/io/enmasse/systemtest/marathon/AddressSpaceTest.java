package io.enmasse.systemtest.marathon;

import io.enmasse.systemtest.AddressSpace;
import io.enmasse.systemtest.AddressSpaceType;
import io.enmasse.systemtest.Destination;
import io.enmasse.systemtest.Logging;
import io.enmasse.systemtest.amqp.AmqpClient;
import io.enmasse.systemtest.amqp.AmqpClientFactory;
import io.enmasse.systemtest.standard.QueueTest;
import io.enmasse.systemtest.standard.TopicTest;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

public class AddressSpaceTest extends AuthenticationTest {

    @Test
    public void testCreateDeleteAddressSpaceLong() throws Exception{

        runTestInLoop(60, () -> {
            AddressSpace addressSpace = new AddressSpace("test-create-delete-addrspace-brokered",
                    "test-create-delete-addrspace-brokered",
                    AddressSpaceType.BROKERED);
            createAddressSpace(addressSpace, "none");
            Logging.log.info("Address space created");

            doAddressTest(addressSpace, "test-topic-createdelete-brokered-%d",
                    "test-queue-createdelete-brokered-%d");

            deleteAddressSpace(addressSpace);
            Logging.log.info("Address space removed");
            Thread.sleep(10000);
        });
    }

    @Test
    public void testCreateDeleteAddressesLong() throws Exception{
        AddressSpace addressSpace = new AddressSpace("test-create-delete-addresses-brokered",
                "test-create-delete-addresses-brokered",
                AddressSpaceType.BROKERED);
        createAddressSpace(addressSpace, "none");

        runTestInLoop(30, () -> {
            doAddressTest(addressSpace, "test-topic-createdelete-brokered-%d",
                    "test-queue-createdelete-brokered-%d");
            Thread.sleep(10000);
        });
    }

    @Test
    public void testCreateDeleteAddressesWithAuthLong() throws Exception {
        Logging.log.info("test testCreateDeleteAddressesWithAuthLong");
        AddressSpace addressSpace = new AddressSpace("test-create-delete-addresses-auth-brokered",
                AddressSpaceType.BROKERED);
        createAddressSpace(addressSpace, "standard");

        String username = "test-user";
        String password = "test-user";

        createUser(addressSpace, username, password);

        runTestInLoop(30, () -> {
            doAddressTest(addressSpace, "test-topic-createdelete-auth-brokered-%d",
                    "test-queue-createdelete-auth-brokered-%d", username, password);
            Thread.sleep(10000);
        });
    }

    private void doAddressTest(AddressSpace addressSpace, String topicPattern,
                       String queuePattern, String username, String password) throws Exception{
        List<Destination> queueList = new ArrayList<>();
        List<Destination> topicList = new ArrayList<>();

        int destinationCount = 20;

        for(int i = 0; i < destinationCount; i++){
            queueList.add(Destination.queue(String.format(queuePattern, i)));
            topicList.add(Destination.topic(String.format(topicPattern, i)));
        }

        AmqpClient queueClient;
        AmqpClient topicClient;

        setAddresses(addressSpace, queueList.toArray(new Destination[0]));
        for(Destination queue : queueList){
            queueClient = amqpClientFactory.createQueueClient(addressSpace);
            queueClient.getConnectOptions().setUsername(username).setPassword(password);

            QueueTest.runQueueTest(queueClient, queue, 1024);
        }

        setAddresses(addressSpace, topicList.toArray(new Destination[0]));

        for(Destination topic : topicList){
            topicClient = amqpClientFactory.createTopicClient(addressSpace);
            topicClient.getConnectOptions().setUsername(username).setPassword(password);

            TopicTest.runTopicTest(topicClient, topic, 1024);
        }

        deleteAddresses(addressSpace, queueList.toArray(new Destination[0]));
        deleteAddresses(addressSpace, topicList.toArray(new Destination[0]));
    }

    private void doAddressTest(AddressSpace addressSpace, String topicPattern, String queuePattern) throws Exception{
        doAddressTest(addressSpace, topicPattern, queuePattern, "test", "test");
    }
}

package keystoremanager;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import javafx.application.Application;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.control.Menu;
import javafx.scene.control.MenuBar;
import javafx.scene.control.MenuItem;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextArea;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.stage.StageStyle;

/**
 * Currently supprots
 * <p>
 * keystore type = jceks <br>
 * Provider = SunJCE <br>
 * Certificate type = X.509
 * 
 * @author Rahul Bhawsar
 */
public class KeyStoreManager extends Application
{
    private String keyStoreType = "jceks";// default value;

    private String provider = "SunJCE";// default value;

    private char[] password;

    private File KeyStoreFile = null;

    private ListView<String> list = new ListView<String>();

    private Enumeration<String> aliases = null;

    private ObservableList<String> data = FXCollections.observableArrayList();

    private MenuItem menuAddCertificate = null;

    private KeyStore keystore = null;

    @Override
    public void start(final Stage primaryStage)
    {

        VBox vbox = new VBox();
        MenuBar menuBar = new MenuBar();
        Menu menuKeystore = new Menu("KeyStore");
        MenuItem menuOpen = new MenuItem("Open Key Store");
        MenuItem menuClose = new MenuItem("Close Key Store");
        menuClose.setOnAction(new EventHandler<ActionEvent>()
        {

            @Override
            public void handle(ActionEvent actionEvent)
            {
                // Close everything.
                list.setVisible(false);
                menuAddCertificate.setDisable(true);
            }

        });
        menuOpen.setOnAction(new EventHandler<ActionEvent>()
        {

            @Override
            public void handle(ActionEvent actionEvent)
            {
                FileChooser fileChooser = new FileChooser();
                fileChooser.setTitle("Select a Keystore...");
                KeyStoreFile = fileChooser.showOpenDialog(primaryStage);
                if (KeyStoreFile != null)
                    getKeyStorePassword(primaryStage);
            }

        });
        menuAddCertificate = new MenuItem("Add Certificate to Key Store");
        menuAddCertificate.setDisable(true);
        menuAddCertificate.setOnAction(new EventHandler<ActionEvent>()
        {

            @Override
            public void handle(ActionEvent arg0)
            {
                FileChooser fileChooser = new FileChooser();
                fileChooser.setTitle("Select a Certificate...");
                File certFile = fileChooser.showOpenDialog(primaryStage);

                try (InputStream in = new FileInputStream(certFile);)
                {
                    if (certFile != null)
                    {

                        CertificateFactory cf = CertificateFactory.getInstance("X.509");
                        X509Certificate certificate = (X509Certificate)cf.generateCertificate(in);
                        updateKeyStore(certificate);
                    }
                }
                catch (CertificateException | IOException ex)
                {
                    ex.printStackTrace();
                }
            }

        });

        MenuItem menuCreate = new MenuItem("Create New Key Store");
        MenuItem menuExit = new MenuItem("Exit");
        menuExit.setOnAction(new EventHandler<ActionEvent>()
        {
            public void handle(ActionEvent t)
            {
                System.exit(0);
            }
        });
        menuKeystore.getItems().addAll(menuOpen, menuClose, menuAddCertificate, menuCreate, menuExit);

        menuBar.getMenus().addAll(menuKeystore);
        VBox.setVgrow(list, Priority.ALWAYS);
        Scene scene = new Scene(vbox, 500, 400);
        ((VBox)scene.getRoot()).getChildren().addAll(menuBar);

        list.setItems(data);
        list.setVisible(false);// no data yet
        vbox.getChildren().addAll(list);
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    protected void updateKeyStore(X509Certificate certificate)
    {
        // Add the certificate to the keyStore.
        try (OutputStream op = new FileOutputStream(KeyStoreFile))
        {
            keystore.setCertificateEntry("test", certificate);
            keystore.store(op, password);

        }
        catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException ex)
        {
            ex.printStackTrace();
        }

    }

    public void loadData(Stage primaryStage)
    {
        // try to open the keystore with password and get all the
        // certs in list.

        try (InputStream in = new FileInputStream(KeyStoreFile))
        {
            // TODO below hard coded values should be part of
            // password input dialog box.
            keystore = KeyStore.getInstance(keyStoreType, provider);
            keystore.load(in, password);
            aliases = keystore.aliases();
            while (aliases.hasMoreElements())
            {
                String alias = aliases.nextElement();
                if (keystore.isKeyEntry(alias) == false)
                {
                    java.security.cert.Certificate cert = keystore.getCertificate(alias);
                    data.add("Alias=" + alias + "\n" + cert.toString());
                }

            }

            // Data is loaded.
            list.setVisible(true);
            // Now a certificate can be added.
            menuAddCertificate.setDisable(false);

        }
        catch (NoSuchAlgorithmException | CertificateException | IOException | KeyStoreException
                | NoSuchProviderException ex)
        {
            showError(getStackTrace(ex), primaryStage);
        }
    }

    public void getKeyStorePassword(final Stage primaryStage)
    {
        VBox vbox = new VBox();
        final Stage stage = new Stage(StageStyle.UTILITY);
        stage.setTitle("Enter Password");
        stage.setScene(new Scene(vbox, 200, 70));

        Label label = new Label("Password");
        final PasswordField passwordField = new PasswordField();

        passwordField.setOnAction(new EventHandler<ActionEvent>()
        {
            @Override
            public void handle(ActionEvent actionEvent)
            {
                password = passwordField.getText().toCharArray();
                stage.close();
                loadData(primaryStage);
            }
        });
        vbox.getChildren().addAll(label, passwordField);
        stage.initOwner(primaryStage);
        stage.show();

    }

    public static void main(String[] args)
    {
        launch(args);
    }

    public static void showError(String excString, Stage primaryStage)
    {
        VBox vbox = new VBox();
        final Stage stage = new Stage(StageStyle.TRANSPARENT);
        stage.setTitle("Exception");
        stage.setScene(new Scene(vbox, 300, 300));
        Button btn = new Button("Got it");
        btn.setOnAction(new EventHandler<ActionEvent>()
        {
            @Override
            public void handle(ActionEvent arg0)
            {
                stage.close();
            }

        });

        TextArea textArea = new TextArea(excString);

        vbox.getChildren().addAll(textArea, btn);
        stage.initOwner(primaryStage);
        stage.show();
    }

    /**
     * Converts Exception Stack Trace to String.
     * 
     * @param ex Exception
     * @return String
     */
    private String getStackTrace(Exception ex)
    {
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        ex.printStackTrace(pw);
        return sw.toString();
    }

}

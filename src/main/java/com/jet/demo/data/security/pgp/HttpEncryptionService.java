package com.jet.demo.data.security.pgp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.util.Optional;
import java.util.UUID;
import java.util.logging.Level;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.openpgp.PGPPublicKey;

import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import com.microsoft.azure.functions.ExecutionContext;
import com.microsoft.azure.functions.HttpMethod;
import com.microsoft.azure.functions.HttpRequestMessage;
import com.microsoft.azure.functions.HttpResponseMessage;
import com.microsoft.azure.functions.HttpStatus;
import com.microsoft.azure.functions.OutputBinding;
import com.microsoft.azure.functions.annotation.AuthorizationLevel;
import com.microsoft.azure.functions.annotation.BlobInput;
import com.microsoft.azure.functions.annotation.BlobOutput;
import com.microsoft.azure.functions.annotation.FunctionName;
import com.microsoft.azure.functions.annotation.HttpTrigger;
import com.microsoft.azure.functions.annotation.StorageAccount;

/**
 * Azure Functions with HTTP Trigger.
 */
public class HttpEncryptionService {

	@FunctionName("Warmup")
	public void run(ExecutionContext context) {
		context.getLogger().info("Function App instance is warm 🌞🌞🌞");
	}

	@FunctionName("encryptBlobFile")
	@StorageAccount("Storage_Account_Connection_String")
	public HttpResponseMessage encryptBlobFile(@HttpTrigger(name = "req", methods = {
			HttpMethod.GET }, authLevel = AuthorizationLevel.ANONYMOUS) HttpRequestMessage<Optional<String>> request,
			@BlobInput(name = "input", dataType = "binary", path = "{Query.inputPath}") byte[] content,
			@BlobOutput(name = "output", path = "{Query.outputPath}") OutputBinding<String> outputItem,
			final ExecutionContext context) {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		try {
			String keyVaultName = System.getenv("KEY_VAULT_NAME");
			String keyVaultUri = "https://" + keyVaultName + ".vault.azure.net";

			SecretClient secretClient = new SecretClientBuilder().vaultUrl(keyVaultUri)
					.credential(new DefaultAzureCredentialBuilder().build()).buildClient();
			KeyVaultSecret publicKey = secretClient.getSecret("default_pgp_public_key");
			PGPPublicKey pgpKey = PGPHelperUtil
					.readPublicKey(new ByteArrayInputStream(publicKey.getValue().getBytes()));
			String fileName = UUID.randomUUID().toString();
			FileUtils.writeByteArrayToFile(new File(fileName), content);
			KeyBasedFileProcessor.encryptFile(bos, fileName, pgpKey, true, true);
			outputItem.setValue(bos.toString());
		} catch (Exception e) {
			String errMessage = "Failed encrypting file \"" + request.getQueryParameters().get("inputPath")
					+ "\" to location \"" + request.getQueryParameters().get("outputPath") + "\"";

			context.getLogger().log(Level.SEVERE, errMessage, e);
			return request.createResponseBuilder(HttpStatus.OK)
					.body("ERROR - Encryption failed with message " + e.getLocalizedMessage() + ". " + errMessage)
					.build();
		}
		String succesMsg = "Success encrypting file \"" + request.getQueryParameters().get("inputPath")
				+ "\" to location \"" + request.getQueryParameters().get("outputPath") + "\"";
		context.getLogger().info(succesMsg);
		return request.createResponseBuilder(HttpStatus.OK).body(succesMsg).build();
	}

	@FunctionName("decryptBlobFile")
	@StorageAccount("Storage_Account_Connection_String")
	public HttpResponseMessage decryptBlobFile(@HttpTrigger(name = "req", methods = {
			HttpMethod.GET }, authLevel = AuthorizationLevel.ANONYMOUS) HttpRequestMessage<Optional<String>> request,
			@BlobInput(name = "input", dataType = "binary", path = "{Query.inputPath}") byte[] content,
			@BlobOutput(name = "output", path = "{Query.outputPath}") OutputBinding<String> outputItem,
			final ExecutionContext context) {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		try {
			String keyVaultName = System.getenv("KEY_VAULT_NAME");
			String keyVaultUri = "https://" + keyVaultName + ".vault.azure.net";
			SecretClient secretClient = new SecretClientBuilder().vaultUrl(keyVaultUri)
					.credential(new DefaultAzureCredentialBuilder().build()).buildClient();
			KeyVaultSecret privateKey = secretClient.getSecret("default_pgp_secret_key");
			KeyVaultSecret password = secretClient.getSecret("default_pgp_pass_phrase");
			KeyBasedFileProcessor.decryptBytes(new ByteArrayInputStream(content),
					new ByteArrayInputStream(privateKey.getValue().getBytes()), password.getValue().toCharArray(), bos);
			outputItem.setValue(bos.toString());
		} catch (Exception e) {
			String errMessage = "Failed encrypting file \"" + request.getQueryParameters().get("inputPath")
					+ "\" to location \"" + request.getQueryParameters().get("outputPath") + "\"";

			context.getLogger().log(Level.SEVERE, errMessage, e);
			return request.createResponseBuilder(HttpStatus.OK)
					.body("ERROR - Encryption failed with message " + e.getLocalizedMessage() + ". " + errMessage)
					.build();
		}
		String succesMsg = "Success encrypting file \"" + request.getQueryParameters().get("inputPath")
				+ "\" to location \"" + request.getQueryParameters().get("outputPath") + "\"";
		context.getLogger().info(succesMsg);
		return request.createResponseBuilder(HttpStatus.OK).body(succesMsg).build();
	}

}

# OCI Configuration Setup Guide

This guide explains where to find the values needed to configure OCI integration in AppManager.

## Required Values

After deployment, you need to update `instance/oci_config.json` on the server with the following values:

1. **user** - Your OCI User OCID
2. **tenancy** - Your OCI Tenancy OCID
3. **region** - Your OCI Region
4. **fingerprint** - API Key Fingerprint (auto-generated during deployment)
5. **compartment_id** - Your Compartment OCID
6. **vcn_id** - Your VCN (Virtual Cloud Network) OCID

## How to Find These Values

### 1. User OCID

**Method 1: OCI Console**
1. Log in to [Oracle Cloud Console](https://cloud.oracle.com/)
2. Click the **User menu** (top right, your username/icon)
3. Select **User Settings**
4. Your **OCID** is displayed at the top of the page (starts with `ocid1.user.oc1..`)

**Method 2: OCI CLI**
```bash
oci iam user list
```

### 2. Tenancy OCID

**Method 1: OCI Console**
1. Log in to [Oracle Cloud Console](https://cloud.oracle.com/)
2. Click the **Tenancy menu** (top left, shows your tenancy name)
3. Select **Tenancy Details**
4. Your **OCID** is displayed (starts with `ocid1.tenancy.oc1..`)

**Method 2: OCI CLI**
```bash
oci iam tenancy get
```

### 3. Region

**Method 1: OCI Console**
1. Look at the **Region selector** in the top right of the OCI Console
2. Common regions:
   - `us-ashburn-1` (US East - Ashburn)
   - `us-phoenix-1` (US West - Phoenix)
   - `eu-frankfurt-1` (EU - Frankfurt)
   - `uk-london-1` (UK - London)
   - `ap-tokyo-1` (Asia Pacific - Tokyo)
   - `ap-sydney-1` (Asia Pacific - Sydney)

**Method 2: From your instance**
- If you're deploying to an Oracle Cloud instance, check which region it's in
- The region is usually visible in the instance details

### 4. Fingerprint

**This is auto-generated during deployment** from your SSH public key.

If you need to regenerate it manually:
```bash
ssh-keygen -lf ssh/ssh-key-2025-12-26.key.pub
```

The fingerprint is the second field (e.g., `SHA256:...` or `MD5:...`)

**Note:** For OCI API keys, you typically need the MD5 fingerprint. To get it:
```bash
openssl rsa -pubout -outform DER -in ssh/ssh-key-2025-12-26.key | openssl md5 -c
```

Or if you've already uploaded the key to OCI:
1. Go to **Identity** → **Users** → Select your user
2. Click **API Keys** in the left menu
3. Find your API key and copy the **Fingerprint**

### 5. Compartment OCID

**Method 1: OCI Console**
1. Navigate to **Identity** → **Compartments**
2. Find your compartment (often named "root" or your project name)
3. Click on the compartment name
4. Copy the **OCID** (starts with `ocid1.compartment.oc1..`)

**Method 2: OCI CLI**
```bash
oci iam compartment list
```

**Note:** You can use the root compartment (your tenancy) or create a specific compartment for your project.

### 6. VCN OCID

**Method 1: OCI Console**
1. Navigate to **Networking** → **Virtual Cloud Networks**
2. Select your VCN (or create one if you don't have one)
3. Click on the VCN name
4. Copy the **OCID** from the VCN Details page (starts with `ocid1.vcn.oc1..`)

**Method 2: OCI CLI**
```bash
oci network vcn list --compartment-id <your-compartment-ocid>
```

**Note:** If you don't have a VCN yet:
1. Go to **Networking** → **Virtual Cloud Networks**
2. Click **Create VCN**
3. Choose **VCN with Internet Connectivity** (recommended)
4. Fill in the details and create
5. Copy the OCID from the VCN Details page

## Complete Configuration Example

After gathering all values, your `instance/oci_config.json` should look like:

```json
{
    "user": "ocid1.user.oc1..aaaaaaaaxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "fingerprint": "aa:bb:cc:dd:ee:ff:11:22:33:44:55:66:77:88:99:aa",
    "tenancy": "ocid1.tenancy.oc1..aaaaaaaaxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "region": "us-ashburn-1",
    "key_file": "~/.oci/oci_api_key.pem",
    "compartment_id": "ocid1.compartment.oc1..aaaaaaaaxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "vcn_id": "ocid1.vcn.oc1..aaaaaaaaxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
}
```

## Setting Up API Key in OCI

Before the OCI integration will work, you need to upload your public key to OCI:

1. **Get your public key:**
   ```bash
   cat ssh/ssh-key-2025-12-26.key.pub
   ```

2. **Upload to OCI:**
   - Go to **Identity** → **Users** → Select your user
   - Click **API Keys** in the left menu
   - Click **Add API Key**
   - Select **Paste Public Key**
   - Paste the contents of `ssh-key-2025-12-26.key.pub`
   - Click **Add**
   - Copy the **Fingerprint** shown (this should match what's in your config)

## Verifying Configuration

After updating the configuration file, you can verify it works:

```bash
# SSH into your server
ssh -i ssh/ssh-key-2025-12-26.key ubuntu@40.233.70.245

# Test OCI connection (if OCI CLI is installed)
cd /opt/appmanager
source AMvenv/bin/activate
python3 -c "from app.utils.oci_manager import get_oci_manager; m = get_oci_manager(); print('OCI configured:', m.is_configured())"
```

## Troubleshooting

### "OCI not configured" error
- Check that `instance/oci_config.json` exists and has no `PLACEHOLDER` values
- Verify the API key file exists at `~/.oci/oci_api_key.pem`
- Ensure the fingerprint matches the one in OCI Console

### "Permission denied" errors
- Verify the API key has been uploaded to OCI
- Check that the user has permissions to manage security lists
- Ensure you're using the correct compartment and VCN OCIDs

### "Could not determine security list ID"
- Make sure `compartment_id` and `vcn_id` are set in `instance/oci_config.json`
- Verify the VCN exists and is accessible from your compartment

## Required IAM Policies

Your user needs these policies to manage security lists:

```hcl
Allow group <your-group> to manage security-lists in compartment <your-compartment>
Allow group <your-group> to read vcns in compartment <your-compartment>
```

Or for the entire tenancy:
```hcl
Allow group <your-group> to manage security-lists in tenancy
Allow group <your-group> to read vcns in tenancy
```

To check/update policies:
1. Go to **Identity** → **Policies**
2. Select your compartment or tenancy
3. Click **Create Policy** or edit existing policy
4. Add the required statements


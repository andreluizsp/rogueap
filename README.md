# rogueap
RogueAP detection method with machine learning

This project proposes a new ML-based technique for the passive verification of APs, implemented in two stages. First, we passively extract behavioral features from the network packets generated by the assessed APs. This set of features encompasses the APs hardware and software capabilities, which are then used to construct its profile. Second, based on the extracted features, we apply a one-class ML classifier to verify the AP against a previously known normal profiles. APs classified as outliers are presumed to originate from rogue APs, thus deemed unreliable for connection. As a result, our proposed scheme can serve as a verification mechanism to assess the reliability of connected APs. Our insight lies in passively evaluating the hardware and software capabilities of APs through a one-class ML technique.

The main contributions of this project are:

• A new dataset encompassing over 357 APs with over 20 hardware and software extracted behavioral features. The dataset presents multiple rogue APs behaviors generated through software-based techniques.

• A new ML-based verification technique to assess the reli ability of connected APs. The proposed model passively identifies rogue APs with up to 0.9 of true-positive rates.

## Project Setup

1) Start by cloning the project (Install git: https://git-scm.com/download):
   
Shell: # git clone --depth=1 https://github.com/andreluizsp/rogueap.git && cd rogueap

3) This will create a new directory called "rogueap" containing the following files:

$ ls

 LICENSE  MakeCSV.py Packets README.md Rogue_OCCS_SVM.ipynb dataset.csv

### Import Rogue_OCCS_SVM.ipynb in Juniper or Google Colab 

https://colab.research.google.com/drive/1rbxLpr-232kK-4MhV1nt5H3Qaaz-ekb7?usp=sharing

#### Import dataset.csv to Goole Drive or change the cell below

df_orig = pd.read_csv('/content/drive/MyDrive/datasets/dataset.csv')

##### Directory Packages vs. Script MakeCSV.py

1) Inside the Packages directory are the packages used in this project (357 Access Points - APs)

2) Script MakeCSV.py must be in the same directory as the .pcaps files to extract the features of all APs with the command below:

   # MakeCSV.py > dataset.csv

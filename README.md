# rogueap
RogueAP detection method with machine learning

This project proposes a new ML-based technique for the passive verification of APs, implemented in two stages. First, we passively extract behavioral features from the network packets generated by the assessed APs. This set of features encompasses the APs hardware and software capabilities, which are then used to construct its profile. Second, based on the extracted features, we apply a one-class ML classifier to verify the AP against a previously known normal profiles. APs classified as outliers are presumed to originate from rogue APs, thus deemed unreliable for connection. As a result, our proposed scheme can serve as a verification mechanism to assess the reliability of connected APs. Our insight lies in passively evaluating the hardware and software capabilities of APs through a one-class ML technique.

The main contributions of this project are:

• A new dataset encompassing over 357 APs with over 20 hardware and software extracted behavioral features. The dataset presents multiple rogue APs behaviors generated through software-based techniques.

• A new ML-based verification technique to assess the reli ability of connected APs. The proposed model passively identifies rogue APs with up to X.X of true-positive rates.

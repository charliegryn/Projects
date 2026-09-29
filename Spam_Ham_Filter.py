import pandas as pd

df = pd.read_csv("spam.csv", encoding='latin-1')

# Data cleaning
# E.g., dataset has extra column named 'unnamed: 2' etc, due to CSV parsing issues
df = df.iloc[:, :2]
# Rename the columns
df.columns = ['label', 'text']

# Encode the labels: convert ham to 0, and spam to 1
df['label_num'] = df['label'].map({'ham': 0, 'spam': 1})
#Show the first few rows to verify
print(df.head())
# Check the class distribution
print(df['label'].value_counts()) #Normal email: 4825, Spam emails: 747

# Load the libraries
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# Feature Engineering: convert the raw text into numberical "Bag of Words" matrix
vectorizer = CountVectorizer()
# X: the feature matrix (Row = emails, Column = word counts)
X = vectorizer.fit_transform(df['text'])
# Y: the target label (0 = Ham, 1 = Spam)  -- Label y is lowercase
y = df['label_num']

# Split the data into Training Dataset and Testing Dataset, e.g., 20% testing
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.2, random_state=42)
# Random seed is only used for result reproducing, you don't need to add it

# Train model
model = MultinomialNB()
model.fit(X_train, y_train)

# Evaluate the model
y_pred = model.predict(X_test)
# Calculate the accuracy
accuracy = accuracy_score(y_test, y_pred)
print(accuracy) # If you choose to use random seed = 42, you should get 97% accuracy
# Print its confusion matrix
print(confusion_matrix(y_test, y_pred))

print(classification_report(y_test, y_pred, target_names = ['Ham', 'Spam']))
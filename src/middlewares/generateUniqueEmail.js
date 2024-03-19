function generateUniqueEmail(prefix) {
    // Generate a random number to make the email unique
    const randomNumber = Math.floor(Math.random() * 10000);
    // Construct the email by combining the prefix and random number
    const email = `${prefix}${randomNumber}@example.com`;
    return email;
  }
  
  // Example usage:
  const uniqueEmail = generateUniqueEmail('user');
  console.log(uniqueEmail); // Output: user1234@example.com
  
  module.exports = { generateUniqueEmail }
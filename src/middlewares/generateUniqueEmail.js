function generateUniqueEmail(prefix) {
    const randomNumber = Math.floor(Math.random() * 10000);
    const email = `${prefix}${randomNumber}@example.com`;
    return email;
  }

  const uniqueEmail = generateUniqueEmail('user');
  console.log(uniqueEmail); 
  
  module.exports = { generateUniqueEmail }
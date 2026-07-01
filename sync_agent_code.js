import fs from 'fs';

const pagePath = 'app/page.tsx';
let page = fs.readFileSync(pagePath, 'utf8');
const pythonCode = fs.readFileSync('python_agent.py', 'utf8');

const regex = /const pythonCodeString = `[\s\S]*?`;/;
const replacement = 'const pythonCodeString = `' + pythonCode.replace(/`/g, '\\`').replace(/\$/g, '\\$') + '`;';

if (regex.test(page)) {
    page = page.replace(regex, replacement);
    fs.writeFileSync(pagePath, page);
    console.log('Successfully updated page.tsx with python_agent.py');
} else {
    console.log('Failed to find pythonCodeString in page.tsx');
}

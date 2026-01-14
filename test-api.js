// Native fetch is used

async function testApi() {
    const response = await fetch('http://localhost:3000/api/explain', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            english: "The decision caused extensive harm.",
            korean: "그 결정은 광범위한 해악을 끼쳤다.",
            selectedWords: ["광범위한", "해악을"]
        }),
    });

    if (!response.ok) {
        console.error("Error:", response.status, await response.text());
        return;
    }

    const data = await response.json();
    console.log(JSON.stringify(data, null, 2));
}

testApi();

